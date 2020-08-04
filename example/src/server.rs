use tonic::{transport::Server, transport::Certificate, Request, Response, Status};
use hello_world::greeter_server::{Greeter, GreeterServer};
use hello_world::{HelloReply, HelloRequest};
use openssl::ssl::{select_next_proto, AlpnError, SslAcceptor, SslVerifyMode, SslFiletype, SslMethod};
use openssl::x509::{X509StoreContextRef,X509Ref};
use x509_parser::pem::pem_to_der;
use x509_parser::parse_x509_der;
use std::borrow::Borrow;

use std::net::SocketAddr;
use tokio::net::TcpListener;
use tonic_openssl::ALPN_H2_WIRE;

pub mod hello_world {
    tonic::include_proto!("helloworld");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    let path_ref = std::env::current_dir().expect("path nonexistent");
    let parent_ref = path_ref.parent();
    let mut path = parent_ref.unwrap().to_owned();
    let mut path1 = path.clone();
    path1.push("tls-keys/server.key");
    let mut path2 = path.clone();
    path2.push("tls-keys/server.pem");
    path.push("tls-keys/client_ca.pem");
    acceptor
        .set_private_key_file(path1, SslFiletype::PEM)
        .unwrap();
    acceptor
        .set_certificate_file(path2, SslFiletype::PEM)
        .unwrap();
    acceptor
        .set_ca_file(path)
        .unwrap();
   
    acceptor.check_private_key().unwrap();
    acceptor.set_alpn_protos(ALPN_H2_WIRE)?;
    
    let mut verify_mode = SslVerifyMode::empty();
    verify_mode.insert(SslVerifyMode::PEER);
    verify_mode.insert(SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    acceptor.set_verify_callback(verify_mode, move |p, x| tls_level_check_auth(p, x));

    acceptor.set_alpn_select_callback(|_ssl, alpn| {
        select_next_proto(ALPN_H2_WIRE, alpn).ok_or(AlpnError::NOACK)
    });
    let acceptor = acceptor.build();

    let addr = "127.0.0.1:50051".parse::<SocketAddr>()?;

    let mut listener = TcpListener::bind(addr).await?;
    let incoming = tonic_openssl::incoming(listener.incoming(), acceptor);

    let greeter = MyGreeter::default();

    println!("GreeterServer listening on {}", addr);

    Server::builder()
        .add_service(GreeterServer::with_interceptor(greeter, app_level_check_auth))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}

#[derive(Default)]
pub struct MyGreeter {}

#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        println!("Got a request in say_hello from {:?}", request.remote_addr());

        if let Some(certs) = request.peer_certs() {
            println!("Got {} peer certs in app level!", certs.len());
        }

        let reply = hello_world::HelloReply {
            message: format!("Hello {}!", request.into_inner().name),
        };
        Ok(Response::new(reply))
    }
}


fn tls_level_check_auth(preverify_ok: bool, x509_ctx: &X509StoreContextRef) -> bool {
   return true;
}



fn app_level_check_auth(req: Request<()>) -> Result<Request<()>, Status> {
    println!("Interceptor Got a request: {:?}", req);

    if let Some(certs) = req.peer_certs() {
        println!("Got {} peer certs!", certs.len());
        let cert : Certificate = certs[0].clone();
        
        let res = pem_to_der(cert.as_ref());
        match res {
            Ok((rem, pem)) => {
                assert!(rem.is_empty());
                //
                assert_eq!(pem.label, String::from("CERTIFICATE"));
                //
                let res_x509 = parse_x509_der(&pem.contents);
                assert!(res_x509.is_ok());
                match res_x509 {
                    Ok((rem, cert)) => {
                        assert!(rem.is_empty());
                        println!("Algo {:?}", cert.signature_algorithm.algorithm.to_string());
                        println!("Issuer {:?}", cert.tbs_certificate.issuer.to_string());
                        println!("Subject {:?}", cert.tbs_certificate.subject.to_string());
                        println!("TTExp {:?}", cert.tbs_certificate.validity.time_to_expiration());
                        assert_eq!(cert.tbs_certificate.version, 2);
                    },
                    _ => println!("x509 parsing failed: {:?}", res_x509),
                }
                },
            _ => panic!("PEM parsing failed: {:?}", res),
        }
    }
    Ok(req)
}