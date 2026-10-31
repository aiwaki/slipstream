//! Public-fixture broker oracle only. Never linked into the candidate adapter.
use serde_json::{json, Value};
use std::{io::Read, path::Path};
use stdcode::StdcodeSerializeExt;
mod account { include!("../../../account_level_fixture.rs"); }
fn bytes(v:&Value, key:&str)->Vec<u8> {hex::decode(v[key].as_str().unwrap()).unwrap()}
fn main() {
    let root=Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut input=String::new();
    std::io::stdin().take(8193).read_to_string(&mut input).unwrap();
    assert!(input.len()<=8192);
    let request:Value=serde_json::from_str(&input).unwrap();
    let output=match request["action"].as_str().unwrap() {
        "sign"=> {
            let name=request["name"].as_str().unwrap();
            assert!(["e3-2048","e65537-2048","e65537-2049"].contains(&name));
            let der=std::fs::read(root.join("compat-public-fixtures").join(format!("{name}-private.der"))).unwrap();
            // Actual Mizaru server type; its single-field private-key DTO is
            // only populated with the deliberately public disposable fixture.
            let secret:mizaru2::SingleSecretKey=stdcode::deserialize(&der.stdcode()).unwrap();
            let blinded=bytes(&request,"blinded");assert!(blinded.len()<=512);
            let blinded:mizaru2::BlindedClientToken=stdcode::deserialize(&blinded.stdcode()).unwrap();
            let signed=secret.blind_sign(&blinded);
            serde_json::to_value(signed).unwrap()
        },
        "verify_single_cache"=> {
            let (token,sig):(mizaru2::ClientToken,mizaru2::SingleUnblindedSignature)=stdcode::deserialize(&bytes(&request,"cache")).unwrap();
            mizaru2::SinglePublicKey::from_der(&bytes(&request,"der")).blind_verify(token,&sig).unwrap();
            json!({"verified":true})
        },
        "verify_connection_cache"=> {
            let (level,token,sig):(account::AccountLevel,mizaru2::ClientToken,mizaru2::UnblindedSignature)=stdcode::deserialize(&bytes(&request,"cache")).unwrap();
            let root=bytes(&request,"root").try_into().unwrap();
            mizaru2::PublicKey::from_bytes(root).blind_verify(token,&sig).unwrap();
            json!({"verified":true,"level":level})
        },
        _=>panic!("unknown public-fixture oracle action"),
    };
    println!("{}",output);
}
