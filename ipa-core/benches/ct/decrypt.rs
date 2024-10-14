use criterion::{criterion_group, criterion_main, Criterion};
use ipa_core::{
    ff::boolean_array::{BA20, BA3, BA8},
    hpke::{Deserializable, IpaPrivateKey, IpaPublicKey, KeyPair, KeyRegistry},
    report::EncryptedOprfReport,
};

pub fn do_decryption() {
    let enc_report_bytes = hex::decode(
        "12854879d86ef277cd70806a7f6bad269877adc95ee107380381caf15b841a7e995e41\
         4c63a9d82f834796cdd6c40529189fca82720714d24200d8a916a1e090b123f27eaf24\
         f047f3930a77e5bcd33eeb823b73b0e9546c59d3d6e69383c74ae72b79645698fe1422\
         f83886bd3cbca9fbb63f7019e2139191dd000000007777772e6d6574612e636f6d",
    )
    .unwrap();

    let enc_report =
        EncryptedOprfReport::<BA8, BA3, BA20, _>::from_bytes(enc_report_bytes.as_slice()).unwrap();

    let pk: Vec<u8> =
        hex::decode("92a6fb666c37c008defd74abf3204ebea685742eab8347b08e2f7c759893947a").unwrap();
    let sk: Vec<u8> =
        hex::decode("53d58e022981f2edbf55fec1b45dbabd08a3442cb7b7c598839de5d7a5888bff").unwrap();

    let key_registry = KeyRegistry::<KeyPair>::from_keys([KeyPair::from((
        IpaPrivateKey::from_bytes(sk.as_slice()).unwrap(),
        IpaPublicKey::from_bytes(pk.as_slice()).unwrap(),
    ))]);

    for _ in 1..10000 {
        enc_report.decrypt(&key_registry).unwrap();
    }
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("criterion_decrypt", |b| b.iter(|| do_decryption()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
