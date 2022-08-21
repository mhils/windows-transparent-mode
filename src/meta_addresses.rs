use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use crate::TransportProtocol;

pub struct MetaAddressGenerator {
    ipv4_addr: [u8; 4],
    ipv4_port: u16,
    ipv6_addr: [u8; 16],
    ipv6_port: u16,
}

impl MetaAddressGenerator {
    pub fn new() -> Self {
        Self {
            ipv4_addr: [127, 42, 0, 1],
            ipv4_port: 0,
            ipv6_addr: [0xfd, 0xa6, 0xf6, 0xe4, 0xad, 0xdb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ipv6_port: 0,
        }
    }

    pub fn next(&mut self, format_like: &SocketAddr, protocol: TransportProtocol) -> SocketAddr {
        match format_like {
            SocketAddr::V4(_) => SocketAddr::V4(self.v4(protocol)),
            SocketAddr::V6(_) => SocketAddr::V6(self.v6(protocol))
        }
    }

    pub fn is_meta_address(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => {
                ip.octets()[..2] == self.ipv4_addr[..2]
            }
            IpAddr::V6(ip) => {
                ip.octets()[..6] == self.ipv6_addr[..6]
            }
        }
    }

    fn v4(&mut self, protocol: TransportProtocol) -> SocketAddrV4 {
        #[allow(unused_assignments)]
        let mut carry = false; // jetbrains borks on uninitialized version
        (self.ipv4_port, carry) = self.ipv4_port.overflowing_add(2);
        if carry {
            (self.ipv4_addr[3], carry) = self.ipv4_addr[3].overflowing_add(1);
            if carry {
                self.ipv4_addr[2] = self.ipv4_addr[2].wrapping_add(1);
            }
        }
        self.ipv4_port += 2;
        let port = self.ipv4_port + (protocol == TransportProtocol::TCP) as u16;
        SocketAddrV4::new(Ipv4Addr::from(self.ipv4_addr), port)
    }


    fn v6(&mut self, protocol: TransportProtocol) -> SocketAddrV6 {
        #[allow(unused_assignments)]
        let mut carry = false; // jetbrains borks on uninitialized version
        (self.ipv6_port, carry) = self.ipv6_port.overflowing_add(2);
        if carry {
            (self.ipv6_addr[15], carry) = self.ipv6_addr[15].overflowing_add(1);
            if carry {
                self.ipv6_addr[14] = self.ipv6_addr[14].wrapping_add(1);
            }
        }
        let port = self.ipv6_port + (protocol == TransportProtocol::TCP) as u16;
        SocketAddrV6::new(Ipv6Addr::from(self.ipv6_addr), port, 0, 0)
    }
}
