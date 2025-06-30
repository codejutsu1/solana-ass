use actix_web::{post, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::AccountMeta,
    pubkey::Pubkey,
};
use spl_token;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bs58;

#[derive(Debug, Deserialize)]
struct MintToRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Serialize)]
struct InstructionAccount {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct MintToResponse {
    success: bool,
    data: InstructionPayload,
}

#[derive(Serialize)]
struct InstructionPayload {
    program_id: String,
    accounts: Vec<InstructionAccount>,
    instruction_data: String,
}

#[post("/token/mint")]
async fn mint_to(req: web::Json<MintToRequest>) -> impl Responder {
    // Parse and validate base58 inputs
    let mint = match bs58::decode(&req.mint).into_vec().ok().and_then(|b| Pubkey::try_from(b.as_slice()).ok()) {
        Some(p) => p,
        None => return HttpResponse::BadRequest().body("Invalid mint address"),
    };
    let destination = match bs58::decode(&req.destination).into_vec().ok().and_then(|b| Pubkey::try_from(b.as_slice()).ok()) {
        Some(p) => p,
        None => return HttpResponse::BadRequest().body("Invalid destination address"),
    };
    let authority = match bs58::decode(&req.authority).into_vec().ok().and_then(|b| Pubkey::try_from(b.as_slice()).ok()) {
        Some(p) => p,
        None => return HttpResponse::BadRequest().body("Invalid authority address"),
    };

    let instruction = match spl_token::instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[], // No multisig signers
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to create instruction"),
    };

    let accounts = instruction
        .accounts
        .iter()
        .map(|a| InstructionAccount {
            pubkey: a.pubkey.to_string(),
            is_signer: a.is_signer,
            is_writable: a.is_writable,
        })
        .collect();

    let response = MintToResponse {
        success: true,
        data: InstructionPayload {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: STANDARD.encode(instruction.data),
        },
    };

    HttpResponse::Ok().json(response)
}

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(mint_to);
}
