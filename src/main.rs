use actix_web::{get, web, post, App, HttpServer, Responder, HttpResponse};
use solana_sdk::signature::{Keypair, Signer};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::{AccountMeta},
    pubkey::Pubkey,
};
use base64;
use bs58;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

#[derive(Serialize)]
struct KeypairResponse {
    success: bool,
    data: KeypairData,
}

#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}


#[derive(Debug, Deserialize)]
struct MintToRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[get("/")]
async fn hello() -> impl Responder {
    "Hello, Actix!"
}

#[post("/keypair")]
async fn generate_keypair() -> impl Responder {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    let response = KeypairResponse {
        success: true,
        data: KeypairData { pubkey, secret },
    };

    HttpResponse::Ok().json(response)
}

#[derive(Debug, Deserialize)]
struct CreateTokenRequest {
    mintAuthority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct MintToResponse {
    success: bool,
    data: InstructionPayload,
}

#[derive(Serialize)]
struct InstructionAccount {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct TokenCreateResponse {
    success: bool,
    data: InstructionPayload,
}

#[derive(Serialize)]
struct InstructionPayload {
    program_id: String,
    accounts: Vec<InstructionAccount>,
    instruction_data: String,
}

#[derive(Debug, Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String, 
}

#[derive(Serialize)]
struct SignMessageResponse {
    success: bool,
    data: Option<SignedMessageData>,
    error: Option<String>,
}

#[derive(Serialize)]
struct SignedMessageData {
    signature: String,    
    public_key: String,   
    message: String,
}

#[derive(Debug, Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String, // base64-encoded
    pubkey: String,    // base58-encoded
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    success: bool,
    data: Option<VerificationResult>,
    error: Option<String>,
}

#[derive(Serialize)]
struct VerificationResult {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Debug, Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SendSolResponse {
    success: bool,
    data: Option<SolTransferPayload>,
    error: Option<String>,
}

#[derive(Serialize)]
struct SolTransferPayload {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Debug, Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct SendTokenResponse {
    success: bool,
    data: Option<SplTokenTransferPayload>,
    error: Option<String>,
}

#[derive(Serialize)]
struct SplTokenTransferPayload {
    program_id: String,
    accounts: Vec<SplTokenTransferAccount>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SplTokenTransferAccount {
    pubkey: String,
    isSigner: bool,
}


#[post("/token/create")]
async fn create_token(req: web::Json<CreateTokenRequest>) -> impl Responder {
    let mint_authority = match bs58::decode(&req.mintAuthority).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => return HttpResponse::BadRequest().body("Invalid mintAuthority"),
        },
        Err(_) => return HttpResponse::BadRequest().body("Invalid base58 in mintAuthority"),
    };

    let mint = match bs58::decode(&req.mint).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => return HttpResponse::BadRequest().body("Invalid mint"),
        },
        Err(_) => return HttpResponse::BadRequest().body("Invalid base58 in mint"),
    };

    let rent_sysvar = solana_sdk::sysvar::rent::id();
    let token_program = spl_token::id();

    let accounts = vec![
        AccountMeta::new(mint, false),
        AccountMeta::new_readonly(mint_authority, true),
        AccountMeta::new_readonly(rent_sysvar, false),
    ];

    // Create the instruction
    let ix = spl_token::instruction::initialize_mint(
        &token_program,
        &mint,
        &mint_authority,
        None, // Freeze authority
        req.decimals,
    )
    .unwrap();

    let accounts_serialized = ix
        .accounts
        .iter()
        .map(|meta| InstructionAccount {
            pubkey: meta.pubkey.to_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        })
        .collect();

    let response = TokenCreateResponse {
        success: true,
        data: InstructionPayload {
            program_id: ix.program_id.to_string(),
            accounts: accounts_serialized,
            instruction_data: base64::engine::general_purpose::STANDARD.encode(ix.data),
        },
    };

    HttpResponse::Ok().json(response)
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

#[post("/message/sign")]
async fn sign_message(req: web::Json<SignMessageRequest>) -> impl Responder {
    let secret_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(bytes) if bytes.len() == 64 => bytes,
        _ => {
            return HttpResponse::BadRequest().json(SignMessageResponse {
                success: false,
                data: None,
                error: Some("Invalid or missing secret key".into()),
            })
        }
    };

    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return HttpResponse::BadRequest().json(SignMessageResponse {
                success: false,
                data: None,
                error: Some("Failed to parse keypair from secret key".into()),
            })
        }
    };

    let signature = keypair.sign_message(req.message.as_bytes());

    let response = SignMessageResponse {
        success: true,
        data: Some(SignedMessageData {
            signature: base64::engine::general_purpose::STANDARD.encode(signature.as_ref()),
            public_key: keypair.pubkey().to_string(),
            message: req.message.clone(),
        }),
        error: None,
    };

    HttpResponse::Ok().json(response)
}

#[post("/message/verify")]
async fn verify_message(req: web::Json<VerifyMessageRequest>) -> impl Responder {
    use solana_sdk::signature::Signature;

    // Decode public key from base58
    let pubkey = match bs58::decode(&req.pubkey).into_vec()
        .ok()
        .and_then(|b| Pubkey::try_from(b.as_slice()).ok()) 
    {
        Some(pk) => pk,
        None => {
            return HttpResponse::BadRequest().json(VerifyMessageResponse {
                success: false,
                data: None,
                error: Some("Invalid base58 public key".to_string()),
            });
        }
    };

    // Decode signature from base64
    let signature_bytes = match base64::engine::general_purpose::STANDARD.decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return HttpResponse::BadRequest().json(VerifyMessageResponse {
                success: false,
                data: None,
                error: Some("Invalid base64 signature".to_string()),
            });
        }
    };

    if signature_bytes.len() != 64 {
        return HttpResponse::BadRequest().json(VerifyMessageResponse {
            success: false,
            data: None,
            error: Some("Invalid signature length".to_string()),
        });
    }

    // Build signature object
    let signature = match solana_sdk::signature::Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            return HttpResponse::BadRequest().json(VerifyMessageResponse {
                success: false,
                data: None,
                error: Some("Failed to parse signature".into()),
            });
        }
    };

    // Perform verification
    let is_valid = signature.verify(pubkey.as_ref(), req.message.as_bytes());

    // Return result
    HttpResponse::Ok().json(VerifyMessageResponse {
        success: true,
        data: Some(VerificationResult {
            valid: is_valid,
            message: req.message.clone(),
            pubkey: req.pubkey.clone(),
        }),
        error: None,
    })
}

#[post("/send/sol")]
async fn send_sol(req: web::Json<SendSolRequest>) -> impl Responder {
    use solana_sdk::system_instruction;
    use solana_sdk::instruction::Instruction;

    // Parse and validate `from` pubkey
    let from_pubkey = match bs58::decode(&req.from).into_vec()
        .ok()
        .and_then(|b| Pubkey::try_from(b.as_slice()).ok())
    {
        Some(pk) => pk,
        None => {
            return HttpResponse::BadRequest().json(SendSolResponse {
                success: false,
                data: None,
                error: Some("Invalid 'from' address".to_string()),
            });
        }
    };

    // Parse and validate `to` pubkey
    let to_pubkey = match bs58::decode(&req.to).into_vec()
        .ok()
        .and_then(|b| Pubkey::try_from(b.as_slice()).ok())
    {
        Some(pk) => pk,
        None => {
            return HttpResponse::BadRequest().json(SendSolResponse {
                success: false,
                data: None,
                error: Some("Invalid 'to' address".to_string()),
            });
        }
    };

    // Validate lamports (non-zero, reasonable cap to prevent abuse)
    if req.lamports == 0 {
        return HttpResponse::BadRequest().json(SendSolResponse {
            success: false,
            data: None,
            error: Some("Transfer amount must be greater than 0".to_string()),
        });
    }

    // Build instruction
    let instruction: Instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, req.lamports);

    let response = SendSolResponse {
        success: true,
        data: Some(SolTransferPayload {
            program_id: instruction.program_id.to_string(),
            accounts: instruction.accounts.iter().map(|acc| acc.pubkey.to_string()).collect(),
            instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
        }),
        error: None,
    };

    HttpResponse::Ok().json(response)
}

#[post("/send/token")]
async fn send_token(req: web::Json<SendTokenRequest>) -> impl Responder {
    use spl_associated_token_account::get_associated_token_address;

    // Decode and validate all addresses
    let owner = match bs58::decode(&req.owner).into_vec().ok().and_then(|b| Pubkey::try_from(b.as_slice()).ok()) {
        Some(pk) => pk,
        None => return HttpResponse::BadRequest().json(SendTokenResponse {
            success: false,
            data: None,
            error: Some("Invalid owner address".to_string()),
        }),
    };

    let destination = match bs58::decode(&req.destination).into_vec().ok().and_then(|b| Pubkey::try_from(b.as_slice()).ok()) {
        Some(pk) => pk,
        None => return HttpResponse::BadRequest().json(SendTokenResponse {
            success: false,
            data: None,
            error: Some("Invalid destination address".to_string()),
        }),
    };

    let mint = match bs58::decode(&req.mint).into_vec().ok().and_then(|b| Pubkey::try_from(b.as_slice()).ok()) {
        Some(pk) => pk,
        None => return HttpResponse::BadRequest().json(SendTokenResponse {
            success: false,
            data: None,
            error: Some("Invalid mint address".to_string()),
        }),
    };

    if req.amount == 0 {
        return HttpResponse::BadRequest().json(SendTokenResponse {
            success: false,
            data: None,
            error: Some("Amount must be greater than 0".to_string()),
        });
    }

    // Compute source and destination token accounts
    let source_token_account = get_associated_token_address(&owner, &mint);
    let destination_token_account = get_associated_token_address(&destination, &mint);

    // Build the instruction
    let instruction = match spl_token::instruction::transfer(
        &spl_token::id(),
        &source_token_account,
        &destination_token_account,
        &owner,
        &[],
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(_) => return HttpResponse::InternalServerError().json(SendTokenResponse {
            success: false,
            data: None,
            error: Some("Failed to create token transfer instruction".to_string()),
        }),
    };

    // Convert accounts
    let accounts: Vec<SplTokenTransferAccount> = instruction
        .accounts
        .iter()
        .map(|meta| SplTokenTransferAccount {
            pubkey: meta.pubkey.to_string(),
            isSigner: meta.is_signer,
        })
        .collect();

    // Encode instruction data in base64
    let payload = SplTokenTransferPayload {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    };

    HttpResponse::Ok().json(SendTokenResponse {
        success: true,
        data: Some(payload),
        error: None,
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(hello)
            .service(generate_keypair)
            .service(create_token)
            .service(mint_to)
            .service(sign_message)
            .service(verify_message)
            .service(send_sol)
            .service(send_token)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
