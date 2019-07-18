use std::env;
use std::net::SocketAddr;

use futures::{Future, Stream};
use tokio::net::TcpListener;
use tokio::runtime::current_thread;
use tokio_socks5::server::Connection;
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
    let connections = listener.incoming().map(move |socket| {
        let connection = Connection::new(resolver.clone());
        connection.serve(socket)
    });
    let server = connections
        .for_each(move |connection| {
            let handle_conn = connection.then(move |res| {
                match res {
                    Ok((a, b)) => println!("proxied {}/{} bytes for blah", a, b),
                    Err(e) => println!("error for blah: {}", e),
                };
                Ok(())
            });
            Ok(current_thread::spawn(handle_conn))
        })
        .map_err(drop);

    // Now that we've got our server as a future ready to go, let's run it!
    //
    // This `run` method will return the resolution of the future itself, but
    // our `server` futures will resolve to `io::Result<()>`, so we just want to
    // assert that it didn't hit an error.
    current_thread::run(server.join(background).map(|_| ()));
}
