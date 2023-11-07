use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response, Headers};

use zkml::{
    model::ModelCircuit,
    utils::{
      proving_kzg::{verify_circuit_kzg, verify_kzg},
    },
  };

use halo2_proofs::{
    dev::MockProver,
    halo2curves::{
      bn256::{Bn256, Fq, Fq2, Fr, G1Affine, G2Affine},
      ff::PrimeField, CurveAffine,
    },
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, VerifyingKey},
    poly::{
      commitment::{Params, ParamsProver},
      kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
      },
    },
    transcript::{
      Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
    SerdeFormat,
  };
  use halo2_gadgets::poseidon::{
    primitives::{ConstantLength, Domain, Hash},
    PaddedWord,
  };

use std::{io::{BufReader, Cursor}, array};
use std::convert::TryInto;
use base64::{engine::general_purpose, Engine};

#[macro_use]
mod util;


static TEST_VKEY_URL: &str = "https://project-vail.storage.googleapis.com/mnist-2023-10-18/vkey";
static TEST_PROOF_URL: &str = "https://project-vail.storage.googleapis.com/mnist-2023-10-18/proof";
static TEST_MODEL_CONFIG_URL: &str = "https://project-vail.storage.googleapis.com/mnist-2023-10-18/config.msgpack";
static TEST_PUBLIC_VALUES_URL: &str = "https://project-vail.storage.googleapis.com/mnist-2023-10-18/public_vals";
static TEST_KZG_PARAMS_URL: &str = "https://project-vail.storage.googleapis.com/mnist-2023-10-18/params/15.params";


#[wasm_bindgen(start)]
pub async fn main() {
    std::panic::set_hook(Box::new(console_error_panic_hook::hook));

    log!("Initializing VAIL Verifier Extension...");

    let vkey = fetch_bytes_from_url(TEST_VKEY_URL.to_string()).await.unwrap();
    let proof = fetch_bytes_from_url(TEST_PROOF_URL.to_string()).await.unwrap();
    let config = fetch_bytes_from_url(TEST_MODEL_CONFIG_URL.to_string()).await.unwrap();
    let pub_vals = fetch_vec_from_url(TEST_PUBLIC_VALUES_URL.to_string()).await.unwrap();
    let kzg_params = fetch_bytes_from_url(TEST_KZG_PARAMS_URL.to_string()).await.unwrap();

    log!("Gathered artifacts for verifier...");

    verify_proof_with_kzg(&vkey, &proof, &config,&pub_vals, &kzg_params);


}

fn verify_proof_with_kzg(vkey: &Uint8Array, proof: &Uint8Array, config: &Uint8Array, public_vals: &Vec<Fr>, kzg_params: &Uint8Array) {
    // Deserialize the vkey
    let vkey_bytes = vkey.to_vec();
    log!("vkey_bytes: {:?}", &vkey_bytes.len());

    let mut reader = BufReader::new(Cursor::new(vkey_bytes));
    let vk: halo2_proofs::plonk::VerifyingKey<G1Affine> = VerifyingKey::read::<BufReader<Cursor<Vec<u8>>>, ModelCircuit<Fr>>(
      &mut reader,
    SerdeFormat::RawBytes,
    (),
    ).unwrap();

    log!("Deserialized VKey...");

    // Deserialize the proof
    let proof_bytes = proof.to_vec();
    log!("proof_bytes: {:?}", &proof_bytes.len());

    log!("Deserialized Proof...");

    // Load the circuit from the config
    let config_buf = config.to_vec();
    let msg_pack_config = rmp_serde::from_slice(&config_buf).unwrap();
    let circuit = ModelCircuit::<Fr>::generate_from_msgpack(msg_pack_config, false);

    log!("Loaded Circuit...");

    // Load the KZG params
    let kzg_bytes = kzg_params.to_vec();
    log!("kzg_bytes: {:?}", &kzg_bytes.len());
    let mut reader = BufReader::new(Cursor::new(kzg_bytes));
    let params = ParamsKZG::<Bn256>::read(&mut reader).expect("Failed to read params");

    log!("Loaded KZG Params...");

    let strategy = SingleStrategy::new(&params);
    let mut transcript: Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>> = Blake2bRead::<_, _, Challenge255<_>>::init(&proof_bytes[..]);
  
    // verify the proof
    log!("Running verifier...");

    // verify_kzg(&params, &vk, strategy, &public_vals, transcript)
    match verify_proof::<
      KZGCommitmentScheme<Bn256>,
      VerifierSHPLONK<'_, Bn256>,
      Challenge255<G1Affine>,
      Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
      halo2_proofs::poly::kzg::strategy::SingleStrategy<'_, Bn256>,
    >(&params, &vk, strategy, &[&[&public_vals]], &mut transcript) {
      Ok(_) => log!("Proof verified!"),
      Err(e) => log!("Proof verification failed: {:?}", e),
    };

  }




async fn fetch_bytes_from_url(url: String) -> Result<Uint8Array, JsValue> {

  let mut opts = RequestInit::new();
  opts.method("GET");
  opts.mode(RequestMode::Cors);

  let request = Request::new_with_str_and_init(&url, &opts)?;

  let window = web_sys::window().unwrap();
  let response = JsFuture::from(window.fetch_with_request(&request)).await?;

  assert!(response.is_instance_of::<Response>());
  assert!(response.has_type::<Response>());

  let response = response.clone().dyn_into::<Response>().unwrap();

  match response.array_buffer() {
      Ok(v) => {
          let val = JsFuture::from(v.clone()).await.unwrap();
          let array_buf = Uint8Array::new(&val);
          log!("Response Val ({:?}): {:?}", &url, &array_buf.length());
          return Ok(array_buf);
      },
      Err(e) => {
          let err_string = format!("Error fetching url: {:?}", url);
          return Err(JsValue::from_str(&err_string));
      }
  }
}

async fn fetch_vec_from_url(url: String) -> Result<Vec<Fr>, JsValue> {
  let array_buf = fetch_bytes_from_url(url).await?;

  log!("Array Buf: {:?}", array_buf.length());

  // Convert Uint8Array to a Vec<u8>
  let mut data = vec![0; array_buf.length() as usize];
  array_buf.copy_to(&mut data);

  log!("Blob: {:?}", data.len());


  let public_vals: Vec<Fr> = data
    .chunks(32)
    .map(|chunk| Fr::from_bytes(chunk.try_into().expect("conversion failed")).unwrap())
    .collect();

  return Ok(public_vals);
}

