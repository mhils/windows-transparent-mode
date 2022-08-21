use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::{env, io, process, thread};
use std::time::Duration;
use windivert::{WinDivert, WinDivertEvent, WinDivertFlags, WinDivertLayer, WinDivertPacket, WinDivertParsedPacket};

use anyhow::{anyhow, Context, Error, Result};
use log::debug;
use lru_time_cache::{LruCache};
use windivert::address::WinDivertNetworkData;
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags};


mod packet;
mod meta_addresses;

use crate::packet::{ConnectionId, InternetPacket, TransportProtocol};
use crate::meta_addresses::MetaAddressGenerator;


enum Message {
    Packet(WinDivertPacket),
    Lookup(SocketAddr),
}

#[derive(Debug)]
enum ConnectionState<'a> {
    Known(ConnectionAction),
    Unknown(Vec<(WinDivertNetworkData<'a>, InternetPacket)>),
}

#[derive(Debug, Clone)]
enum ConnectionAction {
    None,
    Rewrite(SocketAddr, SocketAddr),
}

fn main() -> Result<()> {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    let mitmproxy_port = args
        .get(1)
        .and_then(|s| s.parse::<u16>().ok())
        .context(anyhow!("Usage: {} <port>", args[0]))?;

    let mitmproxy_pid = get_sockets_info(AddressFamilyFlags::IPV4, ProtocolFlags::TCP)?
        .into_iter()
        .find(|info| info.local_port() == mitmproxy_port)
        .and_then(|info| info.associated_pids.into_iter().next())
        .context(anyhow!("Could not find an application listening port {}.", mitmproxy_port))?;

    log::debug!("Using mitmproxy pid: {}", mitmproxy_pid);


    let (tx, rx) = sync_channel::<Message>(32);

    // We currently rely on handles being automatically closed when the program exits.
    let _icmp_handle = WinDivert::new("icmp", WinDivertLayer::Network, 1042, WinDivertFlags::new().set_drop()).context("Error opening WinDivert handle")?;

    //let filter = format!("tcp || ( udp && ( udp.DstPort == 53 || udp.DstPort == 443 || udp.SrcPort == {} ) )", mitmproxy_port);

    let filter = "tcp";

    log::debug!("Using filter: {}", filter);
    let socket_handle = WinDivert::new("tcp", WinDivertLayer::Socket, 1041, WinDivertFlags::new().set_recv_only().set_sniff())
        .context("Failed to open WinDivert socket handle, the WinDivert filter is likely invalid.")?;
    let network_handle = WinDivert::new(&filter, WinDivertLayer::Network, 1040, WinDivertFlags::new())?;
    let inject_handle = WinDivert::new("false", WinDivertLayer::Network, 1039, WinDivertFlags::new().set_send_only())?;


    // We now spawn three threads that all feed us messages into our channel.
    let tx_clone = tx.clone();
    thread::spawn(move || relay_events(socket_handle, 0, 32, tx_clone));
    let tx_clone = tx.clone();
    thread::spawn(move || relay_events(network_handle, 1520, 8, tx_clone));

    thread::spawn(move || handle_stdin(tx));


    let mut connections = LruCache::<ConnectionId, ConnectionState>::with_expiry_duration(Duration::from_secs(60 * 10));
    let mut meta_address_generator = MetaAddressGenerator::new();

    let mitmproxy_v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, mitmproxy_port));
    let mitmproxy_v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, mitmproxy_port, 0, 0));

    loop {
        let result = rx.recv().unwrap();
        match result {
            Message::Packet(wd_packet) => {
                match wd_packet.parse() {
                    WinDivertParsedPacket::Network { addr, data } => {
                        let packet = match InternetPacket::new(data) {
                            Ok(p) => p,
                            Err(e) => {
                                debug!("Error parsing packet: {:?}", e);
                                continue;
                            }
                        };

                        let is_multicast = packet.src_ip().is_multicast() || packet.dst_ip().is_multicast();
                        let is_loopback_only = packet.src_ip().is_loopback() && packet.dst_ip().is_loopback() && !meta_address_generator.is_meta_address(packet.dst_ip());
                        if is_multicast || is_loopback_only {
                            debug!("skipping multicast={} loopback={}", is_multicast, is_loopback_only);
                            inject_handle.send(WinDivertParsedPacket::Network { addr, data: packet.inner() }).unwrap();
                            continue
                        }

                        // debug!("Received packet: {} {} {}", packet.connection_id(), packet.tcp_flag_str(), packet.payload().len());

                        match connections.get_mut(&packet.connection_id()) {
                            Some(state) => {
                                match state {
                                    ConnectionState::Known(s) => {
                                        //println!("already known");
                                        process_packet(addr, packet, s, &inject_handle)?;
                                    }
                                    ConnectionState::Unknown(packets) => {
                                        //println!("more buffering");
                                        packets.push((addr, packet));
                                    }
                                }
                            }
                            None => {
                                //println!("start buffering");
                                debug!("Adding unknown: {}", packet.connection_id());
                                connections.insert(packet.connection_id(), ConnectionState::Unknown(vec![(addr, packet)]));
                                debug!("Entries now: {}", connections.len());
                            }
                        }
                    }
                    WinDivertParsedPacket::Socket { addr } => {

                        if addr.process_id() == 4 {
                            // We get some operating system events here, which generally are not very useful.
                            debug!("Skipping PID 4");
                            continue;
                        }

                        let proto = match TransportProtocol::try_from(addr.protocol()) {
                            Ok(p) => p,
                            Err(e) => {
                                debug!("Error parsing packet: {:?}", e);
                                continue;
                            }
                        };
                        let connection_id = ConnectionId {
                            proto,
                            src: SocketAddr::from((addr.local_address(), addr.local_port())),
                            dst: SocketAddr::from((addr.remote_address(), addr.remote_port())),
                        };

                        if connection_id.src.ip().is_multicast() || connection_id.dst.ip().is_multicast() {
                            continue;
                        }

                        match addr.event() {
                            WinDivertEvent::SocketConnect | WinDivertEvent::SocketAccept => {

                                let make_entry = match connections.get(&connection_id) {
                                    None => true,
                                    Some(e) => matches!(e, ConnectionState::Unknown(_)),
                                };

                                debug!("{:<15?} is_proxy={} make_entry={} pid={} {}", addr.event(), addr.process_id() == mitmproxy_pid, make_entry, addr.process_id(), connection_id);


                                if make_entry {
                                    debug!("Adding: {} with pid={} ({:?})", &connection_id, addr.process_id(), addr.event());
                                    if addr.process_id() == mitmproxy_pid {
                                        let reverse = ConnectionId {
                                            proto: connection_id.proto,
                                            src: connection_id.dst,
                                            dst: connection_id.src,
                                        };
                                        insert_into_connections(&mut connections, reverse, ConnectionAction::None, &inject_handle)?;
                                        insert_into_connections(&mut connections, connection_id, ConnectionAction::None, &inject_handle)?;
                                    } else {
                                        let meta_address = meta_address_generator.next(&connection_id.dst, connection_id.proto);
                                        let mitm_address = if matches!(&connection_id.dst, SocketAddr::V4(_)) { mitmproxy_v4 } else { mitmproxy_v6 };
                                        let reverse = ConnectionId {
                                            proto: connection_id.proto,
                                            src: mitm_address,
                                            dst: meta_address,
                                        };
                                        insert_into_connections(&mut connections, reverse, ConnectionAction::Rewrite(connection_id.dst, connection_id.src), &inject_handle)?;
                                        insert_into_connections(&mut connections, connection_id, ConnectionAction::Rewrite(meta_address, mitm_address), &inject_handle)?;
                                    };
                                    debug!("Entries now: {}.", connections.len());
                                }
                            }
                            WinDivertEvent::SocketClose => {
                                // We cannot clean up here because there are still final FIN packets on this connection after this.
                                debug!("SocketClose: {}", &connection_id);
                                continue;
                                debug!("Removing: {} with pid={}", &connection_id, addr.process_id());
                                remove_from_connections(&mut connections, connection_id);
                                debug!("Entries left: {}", connections.len());
                            }
                            _ => {}
                        }
                    }
                    _ => unreachable!()
                }
            }
            Message::Lookup( addr) => {
                let mitm_address = if matches!(&addr, SocketAddr::V4(_)) { mitmproxy_v4 } else { mitmproxy_v6 };
                let proto = if (addr.port() & 1) == 1 { TransportProtocol::TCP } else { TransportProtocol::UDP };
                let connection_id = ConnectionId {
                    proto,
                    src: mitm_address,
                    dst: addr,
                };
                match connections.get(&connection_id) {
                    Some(ConnectionState::Known(ConnectionAction::Rewrite(dst, src))) => {
                        println!("{} {} {} {}", src.ip(), src.port(), dst.ip(), dst.port());
                    }
                    s => {
                        println!("error finding destination for meta address {}: {:?}", addr, s);
                    }
                }
            }
        }
    }
}


fn remove_from_connections(connections: &mut LruCache<ConnectionId, ConnectionState>, connection_id: ConnectionId) {
    match connections.remove(&connection_id) {
        Some(ConnectionState::Known(a)) => {
            let reverse_id = match a {
                ConnectionAction::None => {
                    ConnectionId {
                        proto: connection_id.proto,
                        src: connection_id.dst,
                        dst: connection_id.src,
                    }
                }
                ConnectionAction::Rewrite(src, dst) => {
                    ConnectionId {
                        proto: connection_id.proto,
                        src: dst,
                        dst: src,
                    }
                }
            };
            connections.remove(&reverse_id);
        }
        _ => {}
    }
}

fn insert_into_connections(connections: &mut LruCache<ConnectionId, ConnectionState>, key: ConnectionId, state: ConnectionAction, inject_handle: &WinDivert) -> Result<()> {
    let existing = connections.insert(key, ConnectionState::Known(state.clone()));

    if let Some(ConnectionState::Unknown(packets)) = existing {
        for (addr, p) in packets {
            process_packet(addr, p, &state, &inject_handle)?;
        }
    }
    Ok(())
}

fn process_packet(mut addr: WinDivertNetworkData, mut packet: InternetPacket, action: &ConnectionAction, inject_handle: &WinDivert) -> Result<()> {
    let addr2 = (
        addr.impostor(),
        addr.outbound(),
        addr.loopback(),
        addr.event(),
        addr.ipv6(),
        addr.interface_index(),
        addr.subinterface_index(),
    );
    let packet2 = packet.clone();
    let action2 = action.clone();

    let ci = packet.connection_id();

    match action {
        ConnectionAction::None => {}
        ConnectionAction::Rewrite(src, dst) => {

            packet.set_src(src);
            packet.set_dst(dst);
            addr.set_ip_checksum(false);
            addr.set_tcp_checksum(false);
            addr.set_udp_checksum(false);

            /*addr.set_impostor(true);
            // Otherwise
            if packet.hop_limit() == 1 {
                packet.set_hop_limit(2);
            }*/
        }
    }
    // debug!("Injecting {} {} with {:?}", ci, packet.hop_limit(), action);

    inject_handle.send(WinDivertParsedPacket::Network { addr, data: packet.inner() }).context(format!("failed to re-inject packet\n{:?}\n{:?}\n{:?}\n===",addr2, packet2,action2))?;
    Ok(())
}

fn handle_stdin(tx: SyncSender<Message>) {
    let lines = io::stdin().lines();
    for line in lines {

        line.map_err(|e| e.into()).and_then(|line| {
            let addr = line.parse::<SocketAddr>()?;
            tx.send(Message::Lookup(addr)).map_err(|e| e.into())
        }).unwrap_or_else(|e: Error| {
            eprintln!("{}", e);
            process::exit(65);
        });

    }
    process::exit(0);
}

fn relay_events(handle: WinDivert, buffer_size: usize, packet_count: usize, tx: SyncSender<Message>) {
    loop {
        let packets = handle.recv_ex(buffer_size, packet_count);
        match packets {
            Ok(Some(packets)) => {
                for packet in packets {
                    tx.send(Message::Packet(packet)).unwrap();
                }
            }
            Ok(None) => {}
            Err(err) => {
                eprintln!("WinDivert Error: {:?}", err);
                process::exit(74);
            }
        };
    }
}
