use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str;

use futures::{future, Future, Poll};
use log::debug;
use tokio::net::unix::{UnixDatagram, UnixStream};
use tokio::net::TcpStream;
use tokio_io::io::{read_exact, write_all, Window};
use tokio_io::{AsyncRead, AsyncWrite};

use crate::v5;

pub trait ProxiedShutdown {
    fn shutdown(&self, how: Shutdown) -> io::Result<()>;
}

impl ProxiedShutdown for TcpStream {
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.shutdown(how)
    }
}

impl ProxiedShutdown for UnixDatagram {
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.shutdown(how)
    }
}

impl ProxiedShutdown for UnixStream {
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.shutdown(how)
    }
}

pub struct ProxiedIo<T>(T);

impl<T> ProxiedIo<T> {
    pub fn new(io: T) -> Self {
        Self(io)
    }

    pub fn get_ref(&self) -> &T {
        &self.0
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: Read> Read for ProxiedIo<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<T: Write> Write for ProxiedIo<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<T: AsyncRead> AsyncRead for ProxiedIo<T> {}

impl<T: AsyncWrite + ProxiedShutdown> AsyncWrite for ProxiedIo<T> {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        self.0.shutdown(Shutdown::Write)?;
        Ok(().into())
    }
}

fn other(desc: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}

pub enum Destination {
    Name(String, u16),
    Addr(SocketAddr),
}

// Extracts the name and port from addr_buf and returns them, converting
// the name to the form that the trust-dns client can use. If the original
// name can be parsed as an IP address, makes a SocketAddr from that
// address and the port and returns it; we skip DNS resolution in that
// case.
fn name_port(addr_buf: &[u8]) -> io::Result<Destination> {
    // The last two bytes of the buffer are the port, and the other parts of it
    // are the hostname.
    let hostname = &addr_buf[..addr_buf.len() - 2];
    let hostname = str::from_utf8(hostname)
        .map_err(|_e| other("hostname buffer provided was not valid utf-8"))?;
    let pos = addr_buf.len() - 2;
    let port = ((addr_buf[pos] as u16) << 8) | (addr_buf[pos + 1] as u16);

    if let Ok(ip) = hostname.parse() {
        return Ok(Destination::Addr(SocketAddr::new(ip, port)));
    }
    Ok(Destination::Name(hostname.to_string(), port))
}

pub struct Handshake<T>(Box<dyn Future<Item = ConnectionRequest<T>, Error = io::Error> + Send>);

impl<T> Future for Handshake<T>
where
    T: AsyncRead + AsyncWrite + Send + 'static,
{
    type Item = ConnectionRequest<T>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

pub fn handshake<T>(io: T) -> Handshake<T>
where
    T: AsyncRead + AsyncWrite + Send + 'static,
{
    let request = read_exact(io, [0u8]).and_then(|(conn, buf)| match buf[0] {
        v5::VERSION => future::Either::A(handshake_v5(conn)),
        // v4::VERSION => future::Either::B(self.serve_v4(conn)),
        _ => future::Either::B(future::err(other("unknown version"))),
    });
    Handshake(Box::new(request))
}

fn handshake_v5<T>(io: T) -> impl Future<Item = ConnectionRequest<T>, Error = io::Error> + Send
where
    T: AsyncRead + AsyncWrite + Send + 'static,
{
    // First part of the SOCKSv5 protocol is to negotiate a number of
    // "methods". These methods can typically be used for various kinds of
    // proxy authentication and such, but for this server we only implement
    // the `METH_NO_AUTH` method, indicating that we only implement
    // connections that work with no authentication.
    //
    // First here we do the same thing as reading the version byte, we read
    // a byte indicating how many methods. Afterwards we then read all the
    // methods into a temporary buffer.
    //
    // Note that we use `and_then` here to chain computations after one
    // another, but it also serves to simply have fallible computations,
    // such as checking whether the list of methods contains `METH_NO_AUTH`.
    let num_methods = read_exact(io, [0u8]);
    let authenticated = num_methods
        .and_then(|(conn, buf)| read_exact(conn, vec![0u8; buf[0] as usize]))
        .and_then(|(conn, buf)| {
            if buf.contains(&v5::METH_NO_AUTH) {
                Ok(conn)
            } else {
                Err(other("no supported method given"))
            }
        });

    // After we've concluded that one of the client's supported methods is
    // `METH_NO_AUTH`, we "ack" this to the client by sending back that
    // information. Here we make use of the `write_all` combinator which
    // works very similarly to the `read_exact` combinator.
    let part1 = authenticated.and_then(|conn| write_all(conn, [v5::VERSION, v5::METH_NO_AUTH]));

    // Next up, we get a selected protocol version back from the client, as
    // well as a command indicating what they'd like to do. We just verify
    // that the version is still v5, and then we only implement the
    // "connect" command so we ensure the proxy sends that.
    //
    // As above, we're using `and_then` not only for chaining "blocking
    // computations", but also to perform fallible computations.
    let ack = part1.and_then(|(conn, _)| {
        read_exact(conn, [0u8]).and_then(|(conn, buf)| {
            if buf[0] == v5::VERSION {
                Ok(conn)
            } else {
                Err(other("didn't confirm with v5 version"))
            }
        })
    });

    let command = ack.and_then(|conn| {
        read_exact(conn, [0u8]).and_then(|(conn, buf)| {
            if buf[0] == v5::CMD_CONNECT {
                Ok(conn)
            } else {
                Err(other("unsupported command"))
            }
        })
    });

    // After we've negotiated a command, there's one byte which is reserved
    // for future use, so we read it and discard it. The next part of the
    // protocol is to read off the address that we're going to proxy to.
    // This address can come in a number of forms, so we read off a byte
    // which indicates the address type (ATYP).
    //
    // Depending on the address type, we then delegate to different futures
    // to implement that particular address format.
    let resv = command.and_then(|c| read_exact(c, [0u8]).map(|c| c.0));
    let atyp = resv.and_then(|c| read_exact(c, [0u8]));
    let request = atyp.and_then(move |(c, buf)| {
        match buf[0] {
            // For IPv4 addresses, we read the 4 bytes for the address as
            // well as 2 bytes for the port.
            v5::ATYP_IPV4 => future::Either::A(future::Either::A(read_exact(c, [0u8; 6]).map(
                |(io, buf)| {
                    let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                    let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
                    let addr = SocketAddrV4::new(addr, port);
                    let destination = Destination::Addr(SocketAddr::V4(addr));
                    ConnectionRequest { io, destination }
                },
            ))),

            // For IPv6 addresses there's 16 bytes of an address plus two
            // bytes for a port, so we read that off and then keep going.
            v5::ATYP_IPV6 => future::Either::A(future::Either::B(read_exact(c, [0u8; 18]).map(
                |(io, buf)| {
                    let a = ((buf[0] as u16) << 8) | (buf[1] as u16);
                    let b = ((buf[2] as u16) << 8) | (buf[3] as u16);
                    let c = ((buf[4] as u16) << 8) | (buf[5] as u16);
                    let d = ((buf[6] as u16) << 8) | (buf[7] as u16);
                    let e = ((buf[8] as u16) << 8) | (buf[9] as u16);
                    let f = ((buf[10] as u16) << 8) | (buf[11] as u16);
                    let g = ((buf[12] as u16) << 8) | (buf[13] as u16);
                    let h = ((buf[14] as u16) << 8) | (buf[15] as u16);
                    let addr = Ipv6Addr::new(a, b, c, d, e, f, g, h);
                    let port = ((buf[16] as u16) << 8) | (buf[17] as u16);
                    let addr = SocketAddrV6::new(addr, port, 0, 0);
                    let destination = Destination::Addr(SocketAddr::V6(addr));
                    ConnectionRequest { io, destination }
                },
            ))),

            // The SOCKSv5 protocol not only supports proxying to specific
            // IP addresses, but also arbitrary hostnames. This allows
            // clients to perform hostname lookups within the context of the
            // proxy server rather than the client itself.
            //
            // Since the first publication of this code, several
            // futures-based DNS libraries appeared, and as a demonstration
            // of integrating third-party asynchronous code into our chain,
            // we will use one of them, TRust-DNS.
            //
            // The protocol here is to have the next byte indicate how many
            // bytes the hostname contains, followed by the hostname and two
            // bytes for the port. To read this data, we execute two
            // respective `read_exact` operations to fill up a buffer for
            // the hostname.
            //
            // Finally, to perform the "interesting" part, we process the
            // buffer and pass the retrieved hostname to a query future if
            // it wasn't already recognized as an IP address. The query is
            // very basic: it asks for an IPv4 address with a timeout of
            // five seconds. We're using TRust-DNS at the protocol level,
            // so we don't have the functionality normally expected from a
            // stub resolver, such as sorting of answers according to RFC
            // 6724, more robust timeout handling, or resolving CNAME
            // lookups.
            v5::ATYP_DOMAIN => future::Either::B(future::Either::A(
                read_exact(c, [0u8])
                    .and_then(|(conn, buf)| read_exact(conn, vec![0u8; buf[0] as usize + 2]))
                    .and_then(move |(io, buf)| {
                        name_port(&buf)
                            .map(move |destination| ConnectionRequest { io, destination })
                    }),
            )),

            n => {
                let msg = format!("unknown ATYP received: {}", n);
                future::Either::B(future::Either::B(future::err(other(&msg))))
            }
        }
    });
    request
}

pub struct ConnectionRequest<T> {
    io: T,
    destination: Destination,
}

impl<T> ConnectionRequest<T> {
    pub fn destination(&self) -> &Destination {
        &self.destination
    }
}

impl<T> ConnectionRequest<T>
where
    T: AsyncRead + AsyncWrite + Send,
{
    // need to add a reject
    pub fn accept(self, outgoing: &SocketAddr) -> impl Future<Item = T, Error = io::Error> + Send {
        debug!("connected to {}, sending socks5 reply", outgoing);
        let mut resp = [0u8; 32];

        // VER - protocol version
        resp[0] = 5;

        // REP - "reply field" -- what happened with the actual connect.
        //
        // In theory this should reply back with a bunch more kinds of
        // errors if possible, but for now we just recognize a few concrete
        // errors.
        resp[1] = 0;

        // RSV - reserved
        resp[2] = 0;

        // ATYP, BND.ADDR, and BND.PORT
        //
        // These three fields, when used with a "connect" command
        // (determined above), indicate the address that our proxy
        // connection was bound to remotely. There's a variable length
        // encoding of what's actually written depending on whether we're
        // using an IPv4 or IPv6 address, but otherwise it's pretty
        // standard.
        let pos = match outgoing {
            SocketAddr::V4(ref a) => {
                resp[3] = 1;
                resp[4..8].copy_from_slice(&a.ip().octets()[..]);
                8
            }
            SocketAddr::V6(ref a) => {
                resp[3] = 4;
                let mut pos = 4;
                for &segment in a.ip().segments().iter() {
                    resp[pos] = (segment >> 8) as u8;
                    resp[pos + 1] = segment as u8;
                    pos += 2;
                }
                pos
            }
        };
        resp[pos] = (outgoing.port() >> 8) as u8;
        resp[pos + 1] = outgoing.port() as u8;

        // Slice our 32-byte `resp` buffer to the actual size, as it's
        // variable depending on what address we just encoding. Once that's
        // done, write out the whole buffer to our client.
        //
        // The returned type of the future here will be `(TcpStream,
        // TcpStream)` representing the client half and the proxy half of
        // the connection.
        let mut w = Window::new(resp);
        w.set_end(pos + 2);
        write_all(self.io, w).map(|(c1, _)| {
            debug!("successfully sent socks5 reply");
            c1
        })
    }
}
