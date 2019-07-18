use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str;
use std::sync::Arc;
use std::time::Duration;

use futures::{future, Future, Poll};
use log::debug;
use tokio::net::TcpStream;
use tokio_io::io::{copy, read_exact, shutdown, write_all, Window};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_timer::Timeout;
use trust_dns_resolver::AsyncResolver;

use crate::v5;

pub struct Connection {
    dns: AsyncResolver,
}

impl Connection {
    pub fn new(dns: AsyncResolver) -> Self {
        Self { dns }
    }

    pub fn serve(
        self,
        conn: TcpStream,
    ) -> impl Future<Item = (u64, u64), Error = io::Error> + 'static {
        read_exact(conn, [0u8]).and_then(|(conn, buf)| match buf[0] {
            v5::VERSION => future::Either::A(self.serve_v5(conn)),
            // v4::VERSION => future::Either::B(self.serve_v4(conn)),
            _ => future::Either::B(future::err(other("unknown version"))),
        })
    }

    pub fn serve_v5(
        self,
        conn: TcpStream,
    ) -> impl Future<Item = (u64, u64), Error = io::Error> + 'static {
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
        let num_methods = read_exact(conn, [0u8]);
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
        let addr = mybox(atyp.and_then(move |(c, buf)| {
            match buf[0] {
                // For IPv4 addresses, we read the 4 bytes for the address as
                // well as 2 bytes for the port.
                v5::ATYP_IPV4 => mybox(read_exact(c, [0u8; 6]).map(|(c, buf)| {
                    let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                    let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
                    let addr = SocketAddrV4::new(addr, port);
                    (c, SocketAddr::V4(addr))
                })),

                // For IPv6 addresses there's 16 bytes of an address plus two
                // bytes for a port, so we read that off and then keep going.
                v5::ATYP_IPV6 => mybox(read_exact(c, [0u8; 18]).map(|(conn, buf)| {
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
                    (conn, SocketAddr::V6(addr))
                })),

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
                v5::ATYP_DOMAIN => mybox(
                    read_exact(c, [0u8])
                        .and_then(|(conn, buf)| read_exact(conn, vec![0u8; buf[0] as usize + 2]))
                        .and_then(move |(conn, buf)| {
                            let (name, port) = match name_port(&buf) {
                                Ok(UrlHost::Name(name, port)) => (name, port),
                                Ok(UrlHost::Addr(addr)) => return mybox(future::ok((conn, addr))),
                                Err(e) => return mybox(future::err(e)),
                            };
                            debug!("received name and port: {}:{}", name, port);

                            let ipv4 = self
                                .dns
                                .lookup_ip(name.as_str())
                                .map_err(|e| other(&format!("dns error: {}", e)))
                                .and_then(move |r| {
                                    r.iter()
                                        .next()
                                        .map(|addr| SocketAddr::new(addr, port))
                                        .ok_or_else(|| other("no address records in response"))
                                });
                            mybox(ipv4.map(|addr| {
                                debug!("received addr: {:?}", addr);
                                (conn, addr)
                            }))
                        }),
                ),

                n => {
                    let msg = format!("unknown ATYP received: {}", n);
                    mybox(future::err(other(&msg)))
                }
            }
        }));

        // Now that we've got a socket address to connect to, let's actually
        // create a connection to that socket!
        //
        // To do this, we use our `handle` field, a handle to the event loop, to
        // issue a connection to the address we've figured out we're going to
        // connect to. Note that this `tcp_connect` method itself returns a
        // future resolving to a `TcpStream`, representing how long it takes to
        // initiate a TCP connection to the remote.
        //
        // We wait for the TCP connect to get fully resolved before progressing
        // to the next stage of the SOCKSv5 handshake, but we keep ahold of any
        // possible error in the connection phase to handle it in a moment.
        let connected = mybox(addr.and_then(move |(c, addr)| {
            debug!("proxying to {}", addr);
            TcpStream::connect(&addr).then(move |c2| Ok((c, c2, addr)))
        }));

        // Once we've gotten to this point, we're ready for the final part of
        // the SOCKSv5 handshake. We've got in our hands (c2) the client we're
        // going to proxy data to, so we write out relevant information to the
        // original client (c1) the "response packet" which is the final part of
        // this handshake.
        let handshake_finish = mybox(connected.and_then(|(c1, c2, addr)| {
            debug!("connected to {}, sending socks5 reply", addr);
            let mut resp = [0u8; 32];

            // VER - protocol version
            resp[0] = 5;

            // REP - "reply field" -- what happened with the actual connect.
            //
            // In theory this should reply back with a bunch more kinds of
            // errors if possible, but for now we just recognize a few concrete
            // errors.
            resp[1] = match c2 {
                Ok(..) => 0,
                Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => 5,
                Err(..) => 1,
            };

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
            let addr = match c2.as_ref().map(|r| r.local_addr()) {
                Ok(Ok(addr)) => addr,
                Ok(Err(..)) | Err(..) => addr,
            };
            let pos = match addr {
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
            resp[pos] = (addr.port() >> 8) as u8;
            resp[pos + 1] = addr.port() as u8;

            // Slice our 32-byte `resp` buffer to the actual size, as it's
            // variable depending on what address we just encoding. Once that's
            // done, write out the whole buffer to our client.
            //
            // The returned type of the future here will be `(TcpStream,
            // TcpStream)` representing the client half and the proxy half of
            // the connection.
            let mut w = Window::new(resp);
            w.set_end(pos + 2);
            write_all(c1, w).and_then(|(c1, _)| {
                debug!("successfully sent socks5 reply");
                c2.map(|c2| (c1, c2))
            })
        }));

        // Phew! If you've gotten this far, then we're now entirely done with
        // the entire SOCKSv5 handshake!
        //
        // In order to handle ill-behaved clients, however, we have an added
        // feature here where we'll time out any initial connect operations
        // which take too long.
        //
        // Here we create a timeout future, using the `Timeout::new` method,
        // which will create a future that will resolve to `()` in 10 seconds.
        // We then apply this timeout to the entire handshake all at once by
        // performing a `select` between the timeout and the handshake itself.

        let pair = mybox(
            Timeout::new(handshake_finish, Duration::new(10, 0)).map_err(|_| other("timeout")),
        );

        // At this point we've *actually* finished the handshake. Not only have
        // we read/written all the relevant bytes, but we've also managed to
        // complete in under our allotted timeout.
        //
        // At this point the remainder of the SOCKSv5 proxy is shuttle data back
        // and for between the two connections. That is, data is read from `c1`
        // and written to `c2`, and vice versa.
        //
        // To accomplish this, we put both sockets into their own `Rc` and then
        // create two independent `Transfer` futures representing each half of
        // the connection. These two futures are `join`ed together to represent
        // the proxy operation happening.
        mybox(pair.and_then(|(client, server)| {
            let client_reader = RcStream(Arc::new(client));
            let client_writer = client_reader.clone();
            let server_reader = RcStream(Arc::new(server));
            let server_writer = server_reader.clone();

            let client_to_server = copy(client_reader, server_writer)
                .and_then(|(n, _, server_writer)| shutdown(server_writer).map(move |_| n));

            let server_to_client = copy(server_reader, client_writer)
                .and_then(|(n, _, client_writer)| shutdown(client_writer).map(move |_| n));

            client_to_server.join(server_to_client)
        }))
    }
}

#[derive(Clone)]
struct RcStream(Arc<TcpStream>);

impl Read for RcStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self.0).read(buf)
    }
}

impl Write for RcStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self.0).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&*self.0).flush()
    }
}

impl AsyncRead for RcStream {}

impl AsyncWrite for RcStream {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        self.0.shutdown(Shutdown::Write)?;
        Ok(().into())
    }
}

fn mybox<F: Future + 'static>(f: F) -> Box<Future<Item = F::Item, Error = F::Error>> {
    Box::new(f)
}

fn other(desc: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}

enum UrlHost {
    Name(String, u16),
    Addr(SocketAddr),
}

// Extracts the name and port from addr_buf and returns them, converting
// the name to the form that the trust-dns client can use. If the original
// name can be parsed as an IP address, makes a SocketAddr from that
// address and the port and returns it; we skip DNS resolution in that
// case.
fn name_port(addr_buf: &[u8]) -> io::Result<UrlHost> {
    // The last two bytes of the buffer are the port, and the other parts of it
    // are the hostname.
    let hostname = &addr_buf[..addr_buf.len() - 2];
    let hostname = str::from_utf8(hostname)
        .map_err(|_e| other("hostname buffer provided was not valid utf-8"))?;
    let pos = addr_buf.len() - 2;
    let port = ((addr_buf[pos] as u16) << 8) | (addr_buf[pos + 1] as u16);

    if let Ok(ip) = hostname.parse() {
        return Ok(UrlHost::Addr(SocketAddr::new(ip, port)));
    }
    Ok(UrlHost::Name(hostname.to_string(), port))
}
