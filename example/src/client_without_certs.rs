use hello_world::greeter_client::GreeterClient;
use hello_world::HelloRequest;
use openssl::{
    ssl::{SslConnector, SslMethod, SslFiletype},
};
use tonic_openssl::ALPN_H2_WIRE;
use hyper_openssl::HttpsConnector;
use hyper::{Client, client::connect::HttpConnector, Uri};

pub mod hello_world {
    tonic::include_proto!("helloworld");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();
    let mut client = GreeterClient::connect("http://127.0.0.1:50051").await?;

    let request = tonic::Request::new(HelloRequest {
        name: "Tonic".into(),
    });

    let response = client.say_hello(request).await?;

    println!("RESPONSE={:?}", response);

    Ok(())
}
