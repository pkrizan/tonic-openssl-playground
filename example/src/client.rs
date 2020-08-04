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
    let mut connector = SslConnector::builder(SslMethod::tls())?;
    let path_ref = std::env::current_dir().expect("path nonexistent");
    let parent_ref = path_ref.parent();
    let mut path = parent_ref.unwrap().to_owned();
    let mut path1 = path.clone();
    path1.push("tls-keys/client2.key");
    let mut path2 = path.clone();
    path2.push("tls-keys/client2.pem");
    path.push("tls-keys/ca.pem");
    connector.set_certificate_file(path2, SslFiletype::PEM)?;
    connector.set_private_key_file(path1, SslFiletype::PEM)?;

    connector
       .set_ca_file(path)
       .unwrap();
    connector.set_alpn_protos(ALPN_H2_WIRE)?;

    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let mut https = HttpsConnector::with_connector(http, connector)?;

  
    let hyper = Client::builder().http2_only(true).build(https);

    let uri = Uri::from_static("https://127.0.0.1:50051");

   
    let add_origin = tower::service_fn(|mut req: hyper::Request<tonic::body::BoxBody>| {
        let uri = Uri::builder()
            .scheme(uri.scheme().unwrap().clone())
            .authority(uri.authority().unwrap().clone())
            .path_and_query(req.uri().path_and_query().unwrap().clone())
            .build()
            .unwrap();

        *req.uri_mut() = uri;

        hyper.request(req)
    });

    let mut client = GreeterClient::new(add_origin);

    let request = tonic::Request::new(HelloRequest {
        name: "Tonic".into(),
    });

    let response = client.say_hello(request).await?;

    println!("RESPONSE={:?}", response);

    Ok(())
}
