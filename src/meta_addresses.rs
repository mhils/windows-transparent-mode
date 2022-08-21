use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use crate::TransportProtocol;

pub struct AddrGenerator {
    ipv4_meta_addr: [u8; 4],
    ipv4_meta_port: u16,
    ipv6_meta_addr: [u8; 16],
    ipv6_meta_port: u16,
    ipv4_proxy_addr: SocketAddr,
    ipv6_proxy_addr: SocketAddr,
}

impl AddrGenerator {
    pub fn new(proxy_port: u16) -> Self {
        let ipv4_proxy_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, proxy_port));
        let ipv6_proxy_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, proxy_port, 0, 0));
        Self {
            ipv4_meta_addr: [127, 22, 42, 1],
            ipv4_meta_port: 0,
            ipv6_meta_addr: [0xfd, 0xa6, 0xf6, 0xe4, 0xad, 0xdb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ipv6_meta_port: 0,
            ipv4_proxy_addr,
            ipv6_proxy_addr,
        }
    }

    pub fn next_meta_address(&mut self, format_like: &SocketAddr, protocol: TransportProtocol) -> SocketAddr {
        match format_like {
            SocketAddr::V4(_) => SocketAddr::V4(self.next_meta_address_v4(protocol)),
            SocketAddr::V6(_) => SocketAddr::V6(self.next_meta_address_v6(protocol))
        }
    }

    pub fn is_meta_address(&self, addr: &SocketAddr) -> bool {
        match addr {
            SocketAddr::V4(s) => {
                s.ip().octets()[..3] == self.ipv4_meta_addr[..3]
            }
            SocketAddr::V6(s) => {
                s.ip().octets()[..6] == self.ipv6_meta_addr[..6]
            }
        }
    }

    pub fn decode_proto(&self, addr: &SocketAddr) -> TransportProtocol {
        if (addr.port() & 1) == 1 {
            TransportProtocol::TCP
        } else {
            TransportProtocol::UDP
        }
    }

    pub fn proxy_addr(&self, format_like: &SocketAddr) -> SocketAddr {
        match format_like {
            SocketAddr::V4(_) => self.ipv4_proxy_addr,
            SocketAddr::V6(_) => self.ipv6_proxy_addr,
        }
    }

    fn next_meta_address_v4(&mut self, protocol: TransportProtocol) -> SocketAddrV4 {
        if self.ipv4_meta_port == 65534 {
            self.ipv4_meta_port = 2;
            self.ipv4_meta_addr[3] = self.ipv4_meta_addr[3].wrapping_add(1);
        } else {
            self.ipv4_meta_port += 2;
        }
        let port = self.ipv4_meta_port + (protocol == TransportProtocol::TCP) as u16;
        SocketAddrV4::new(Ipv4Addr::from(self.ipv4_meta_addr), port)
    }


    fn next_meta_address_v6(&mut self, protocol: TransportProtocol) -> SocketAddrV6 {
        if self.ipv6_meta_port == 65534 {
            self.ipv6_meta_port = 2;
            self.ipv6_meta_addr[15] = self.ipv6_meta_addr[15].wrapping_add(1);
        } else {
            self.ipv6_meta_port += 2;
        }
        let port = self.ipv6_meta_port + (protocol == TransportProtocol::TCP) as u16;
        SocketAddrV6::new(Ipv6Addr::from(self.ipv6_meta_addr), port, 0, 0)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::str::FromStr;
    use crate::{AddrGenerator, TransportProtocol};

    fn addr(s: &str) -> SocketAddr {
        SocketAddr::from_str(s).unwrap()
    }

    #[test]
    fn test_address_gen() {
        let mut gen = AddrGenerator::new(42);
        let v4 = addr("127.0.0.1:50321");
        assert_eq!(gen.next_meta_address(&v4, TransportProtocol::TCP), addr("127.22.42.1:3"));
        assert_eq!(gen.next_meta_address(&v4, TransportProtocol::UDP), addr("127.22.42.1:4"));
        assert_eq!(gen.next_meta_address(&v4, TransportProtocol::TCP), addr("127.22.42.1:7"));

        assert_eq!(gen.decode_proto(&addr("127.22.42.1:3")), TransportProtocol::TCP);
        assert_eq!(gen.decode_proto(&addr("127.22.42.1:4")), TransportProtocol::UDP);
        assert_eq!(gen.decode_proto(&addr("127.22.42.1:7")), TransportProtocol::TCP);

        assert_eq!(gen.is_meta_address(&addr("127.22.42.1:3")), true);
        assert_eq!(gen.is_meta_address(&addr("1.1.1.1:53")), false);


        gen.ipv4_meta_port = 65532;
        assert_eq!(gen.next_meta_address(&v4, TransportProtocol::TCP), addr("127.22.42.1:65535"));
        assert_eq!(gen.next_meta_address(&v4, TransportProtocol::TCP), addr("127.22.42.2:3"));


        let v6 = addr("[::1]:50321");
        assert_eq!(gen.next_meta_address(&v6, TransportProtocol::TCP), addr("[fda6:f6e4:addb::]:3"));
        assert_eq!(gen.next_meta_address(&v6, TransportProtocol::UDP), addr("[fda6:f6e4:addb::]:4"));
        gen.ipv6_meta_port = 65532;
        assert_eq!(gen.next_meta_address(&v6, TransportProtocol::TCP), addr("[fda6:f6e4:addb::]:65535"));
        assert_eq!(gen.next_meta_address(&v6, TransportProtocol::TCP), addr("[fda6:f6e4:addb::1]:3"));
    }

     #[test]
    fn test_proxy_addr() {
         let gen = AddrGenerator::new(42);
         assert_eq!(gen.proxy_addr(&addr("127.0.0.1:50321")), addr("127.0.0.1:42"));
         assert_eq!(gen.proxy_addr(&addr("[::1]:50321")), addr("[::1]:42"));
     }
}
