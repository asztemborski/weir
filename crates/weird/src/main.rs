use rcgen::{CertificateParams, KeyPair};
use reqwest::{Certificate, Client};
use serde::Serialize;
use tokio::fs;

#[derive(Serialize)]
struct Req {
    csr: String,
}

#[tokio::main]
async fn main() {
    let cert = Certificate::from_der(fs::read("../ca.der").await.unwrap().as_slice()).unwrap();

    let client = Client::builder()
        .use_rustls_tls()
        .add_root_certificate(cert)
        .build()
        .unwrap();

    let params = CertificateParams::default();
    let key_pair = KeyPair::generate().unwrap();
    let csr_pem = params.serialize_request(&key_pair).unwrap().pem().unwrap();

    let json = Req { csr: csr_pem };
    let res = client
        .post("https://127.0.0.1:42067/enroll")
        .json(&json)
        .send()
        .await
        .unwrap();

    dbg!(res.text().await.unwrap());
}
