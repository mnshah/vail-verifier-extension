use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

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

use std::io::{BufReader, Cursor};

#[macro_use]
mod util;


static TEST_VKEY_URL: &str = "https://storage.googleapis.com/project-vail/mnist-2023-10-18/vkey";
static TEST_PROOF_URL: &str = "https://storage.googleapis.com/project-vail/mnist-2023-10-18/proof";
static TEST_MODEL_CONFIG_URL: &str = "https://storage.googleapis.com/project-vail/mnist-2023-10-18/config.msgpack";
static TEST_PUBLIC_VALUES_URL: &str = "https://storage.googleapis.com/project-vail/mnist-2023-10-18/public_vals";
static TEST_KZG_PARAMS_URL: &str = "https://storage.googleapis.com/project-vail/mnist-2023-10-18/params/15.params";


#[wasm_bindgen(start)]
pub async fn main() {
    std::panic::set_hook(Box::new(console_error_panic_hook::hook));

    log!("Initializing VAIL Verifier Extension...");

    let vkey = fetch_vkey(TEST_VKEY_URL.to_string()).await.unwrap();
    let proof = fetch_proof(TEST_PROOF_URL.to_string()).await.unwrap();
    let config = fetch_model_config(TEST_MODEL_CONFIG_URL.to_string()).await.unwrap();
    let pub_vals = fetch_public_values(TEST_PUBLIC_VALUES_URL.to_string()).await.unwrap();
    let kzg_params = fetch_kzg_params(TEST_KZG_PARAMS_URL.to_string()).await.unwrap();


    verify_proof_with_kzg(vkey, proof, config,pub_vals, kzg_params);


}

fn verify_proof_with_kzg(vkey: JsValue, proof: JsValue, config: JsValue, public_vals: Vec<JsValue>, kzg_params: JsValue) {
    // Deserialize the vkey
    let decoded_bytes = hex::decode(&vkey.as_string().unwrap()).unwrap();
    let mut reader = BufReader::new(Cursor::new(decoded_bytes));
    let vk: halo2_proofs::plonk::VerifyingKey<G1Affine> = VerifyingKey::read::<BufReader<Cursor<Vec<u8>>>, ModelCircuit<Fr>>(
      &mut reader,
    SerdeFormat::RawBytes,
    (),
    ).unwrap();

    // Deserialize the proof
    let proof_bytes = hex::decode(&proof.as_string().unwrap()).unwrap();

    // Load the circuit from the config
    let config_buf = hex::decode(config.as_string().unwrap()).unwrap();
    let config = rmp_serde::from_slice(&config_buf).unwrap();
    let circuit = ModelCircuit::<Fr>::generate_from_msgpack(config, false);

    // Load the public values
    let public_vals: Vec<Fr> = public_vals
    .iter()
    .map(|x| Fr::from_str_vartime(x.as_string().unwrap().as_str()).unwrap())
    .collect();

    // Load the KZG params
    let decoded_bytes = hex::decode(&kzg_params.as_string().unwrap()).unwrap();
    let mut reader = BufReader::new(Cursor::new(decoded_bytes));
    let params = ParamsKZG::<Bn256>::read(&mut reader).expect("Failed to read params");

    let strategy = SingleStrategy::new(&params);
    let transcript: Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>> = Blake2bRead::<_, _, Challenge255<_>>::init(&proof_bytes[..]);
  
    // verify the proof
    verify_kzg(&params, &vk, strategy, &public_vals, transcript)

  }





async fn fetch_vkey(vkey_url: String) -> Result<JsValue, JsValue> {
    let mut opts = RequestInit::new();
    opts.method("GET");
    opts.mode(RequestMode::NoCors);

    let request = Request::new_with_str_and_init(&vkey_url, &opts)?;

    let window = web_sys::window().unwrap();
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;

    // `resp_value` is a `Response` object.
    assert!(resp_value.is_instance_of::<Response>());
    let resp: Response = resp_value.dyn_into().unwrap();

    // Convert this other `Promise` into a rust `Future`.
    let blob = JsFuture::from(resp.blob()?).await?;

    log!("VKEY: {:?}", &blob);

    // Send the JSON response back to JS.
    Ok(blob)
}

async fn fetch_proof(proof_url: String) -> Result<JsValue, JsValue> {
    let mut opts = RequestInit::new();
    opts.method("GET");
    opts.mode(RequestMode::NoCors);
    let request = Request::new_with_str_and_init(&proof_url, &opts)?;

    let window = web_sys::window().unwrap();
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;

    // `resp_value` is a `Response` object.
    assert!(resp_value.is_instance_of::<Response>());
    let resp: Response = resp_value.dyn_into().unwrap();

    // Convert this other `Promise` into a rust `Future`.
    let blob = JsFuture::from(resp.blob()?).await?;

    log!("PROOF: {:?}", &blob);

    // Send the JSON response back to JS.
    Ok(blob)
}

async fn fetch_model_config(model_config_url: String) -> Result<JsValue, JsValue> {
    let mut opts = RequestInit::new();
    opts.method("GET");
    opts.mode(RequestMode::NoCors);
    let request = Request::new_with_str_and_init(&model_config_url, &opts)?;

    let window = web_sys::window().unwrap();
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;

    // `resp_value` is a `Response` object.
    assert!(resp_value.is_instance_of::<Response>());
    let resp: Response = resp_value.dyn_into().unwrap();

    // Convert this other `Promise` into a rust `Future`.
    let blob = JsFuture::from(resp.blob()?).await?;

    log!("MODEL CONFIG: {:?}", &blob);

    // Send the blob response back to JS.
    Ok(blob)
}

async fn fetch_public_values(public_values_url: String) -> Result<Vec<JsValue>, JsValue> {
    let mut opts = RequestInit::new();
    opts.method("GET");
    opts.mode(RequestMode::NoCors);
    let request = Request::new_with_str_and_init(&public_values_url, &opts)?;

    let window = web_sys::window().unwrap();
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;

    // `resp_value` is a `Response` object.
    assert!(resp_value.is_instance_of::<Response>());
    let resp: Response = resp_value.dyn_into().unwrap();

    // Convert this other `Promise` into a rust `Future`.
    let blob = JsFuture::from(resp.blob()?).await?;

    // Create a Uint8Array from the blob
    let uint8_array = js_sys::Uint8Array::new(&blob);

    log!("Blob: {:?}", blob);

    // Convert Uint8Array to a Vec<u8>
    let mut data = Vec::with_capacity(uint8_array.length() as usize);
    uint8_array.copy_to(&mut data);

    // Convert Vec<u8> to a Vec<JsValue>
    let js_values: Vec<JsValue> = data.into_iter().map(|byte| JsValue::from(byte)).collect();

    log!("PUB PARAMS: {:?}", &js_values);

    Ok(js_values)

}


async fn fetch_kzg_params(kzg_params_url: String) -> Result<JsValue, JsValue> {
    let mut opts = RequestInit::new();
    opts.method("GET");
    opts.mode(RequestMode::NoCors);
    let request = Request::new_with_str_and_init(&kzg_params_url, &opts)?;

    let window = web_sys::window().unwrap();
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;

    // `resp_value` is a `Response` object.
    assert!(resp_value.is_instance_of::<Response>());
    let resp: Response = resp_value.dyn_into().unwrap();

    // Convert this other `Promise` into a rust `Future`.
    let blob = JsFuture::from(resp.blob()?).await?;

    log!("PUB PARAMS: {:?}", &blob);

    // Send the blob response back to JS.
    Ok(blob)
}