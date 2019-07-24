use std::env;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr};
use std::sync::Arc;

use futures::{future, Future, Poll, Stream};
use tokio::net::{TcpListener, TcpStream};
use tokio_io::io::{copy, shutdown};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_socks5::server::{self, Destination};
use trust_dns_resolver::AsyncResolver;

fn main() {
    drop(env_logger::init());

    // Take the first command line argument as an address to listen on, or fall
    // back to just some localhost default.
    let addr = env::args().nth(1).unwrap_or("127.0.0.1:8080".to_string());
    let addr = addr.parse::<SocketAddr>().unwrap();

    // Initialize the various data structures we're going to use in our server.
    // Here we create the event loop, the global buffer that all threads will
    // read/write into, and the bound TCP listener itself.
    let listener = TcpListener::bind(&addr).unwrap();

    // This is the address of the DNS server we'll send queries to. If
    // external servers can't be used in your environment, you can substitue
    // your own.
    let (config, opts) = trust_dns_resolver::system_conf::read_system_conf().unwrap();
    let (resolver, background) = AsyncResolver::new(config, opts);
    // let dns = "8.8.8.8:53".parse().unwrap();

    // Construct a future representing our server. This future processes all
    // incoming connections and spawns a new task for each client which will do
    // the proxy work.
    //
    // This essentially means that for all incoming connections, those received
    // from `listener`, we'll create an instance of `Client` and convert it to a
    // future representing the completion of handling that client. This future
    // itself is then *spawned* onto the event loop to ensure that it can
    // progress concurrently with all other connections.
    println!("Listening for socks5 proxy connections on {}", addr);
    let serve = listener
        .incoming()
        .map_err(|e| eprintln!("accept failed = {:?}", e))
        .for_each(move |socket| {
            let resolver = resolver.clone();
            let connection = server::handshake(socket)
                .and_then(|request| {
                    let addr = resolve_addr(resolver, request.destination());

                    // need to add connect timeout
                    addr.and_then(|addr| TcpStream::connect(&addr))
                        .and_then(move |server| {
                            request
                                .accept(&server.peer_addr().unwrap())
                                .map(|client| (client, server))
                        })
                        .and_then(|(client, server)| {
                            let client_reader = RcStream(Arc::new(client));
                            let client_writer = client_reader.clone();
                            let server_reader = RcStream(Arc::new(server));
                            let server_writer = server_reader.clone();

                            let client_to_server = copy(client_reader, server_writer).and_then(
                                |(n, _, server_writer)| shutdown(server_writer).map(move |_| n),
                            );

                            let server_to_client = copy(server_reader, client_writer).and_then(
                                |(n, _, client_writer)| shutdown(client_writer).map(move |_| n),
                            );

                            client_to_server.join(server_to_client)
                        })
                })
                .then(|result| {
                    match result {
                        Ok((a, b)) => println!("proxied {}/{} for connection", a, b),
                        Err(e) => println!("error for connection: {}", e),
                    }
                    Ok(())
                });
            tokio::spawn(connection)
        });

    // Now that we've got our server as a future ready to go, let's run it!
    //
    // This `run` method will return the resolution of the future itself, but
    // our `server` futures will resolve to `io::Result<()>`, so we just want to
    // assert that it didn't hit an error.
    tokio::run(serve.join(background).map(drop));
}

fn resolve_addr(
    resolver: AsyncResolver,
    dest: &Destination,
) -> impl Future<Item = SocketAddr, Error = io::Error> + Send + 'static {
    match dest {
        Destination::Name(name, port) => {
            let n = name.to_owned();
            let p = port.clone();
            let f = resolver
                .lookup_ip(n.as_str())
                .map_err(|e| other(&format!("dns error: {}", e)))
                .and_then(move |r| {
                    let res: Result<SocketAddr, io::Error> = r
                        .iter()
                        .next()
                        .map(|a| SocketAddr::new(a, p))
                        .ok_or_else(|| other("no address records in response"));
                    res
                })
                .map_err(|_| other("b;ah"));
            future::Either::A(f)
        }
        Destination::Addr(addr) => future::Either::B(future::ok(addr.clone())),
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

fn other(desc: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}
