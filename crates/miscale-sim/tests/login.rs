//! The simulator's login side agrees with mible-auth's.
#![cfg(test)]

use mible_auth::{Login, LoginError, LoginStatus};
use mible_crypto::Token;
use miscale_sim::{SimConfig, SimPhase, SimScale};

/// A synthetic token (miauth's published test vector).
fn token() -> Token {
    Token::from_hex("0cf5615003810d89c233a12a").unwrap()
}

/// Shuttles writes and notifications until both sides fall quiet.
fn run(login: &mut Login, scale: &mut SimScale) -> LoginStatus {
    for _round in 0_u32..64 {
        let mut moved = false;
        while let Some(tx) = login.poll_transmit() {
            scale.handle_write(tx.channel, &tx.data);
            moved = true;
        }
        while let Some(rx) = scale.poll_notify() {
            let _status = login.handle_notify(rx.channel, &rx.data);
            moved = true;
        }
        if !moved {
            return login.status();
        }
    }
    panic!("login and simulator never fell quiet");
}

/// A login with the scale's token succeeds and opens the spec phase.
#[test]
fn login_succeeds() {
    let mut scale = SimScale::new(SimConfig::new(token(), [0x90; 16]), &[]);
    let mut login = Login::new(&token(), [0xa8; 16]);
    assert_eq!(
        run(&mut login, &mut scale),
        LoginStatus::Authenticated,
        "client"
    );
    assert_eq!(scale.phase(), SimPhase::Spec, "simulator");
    assert!(login.session_cipher().is_some(), "cipher");
}

/// A login with another token is caught by the client at the device proof.
#[test]
fn wrong_token_is_caught() {
    let mut scale = SimScale::new(SimConfig::new(token(), [0x90; 16]), &[]);
    let mut login = Login::new(&Token::new([1; 12]), [0xa8; 16]);
    assert_eq!(
        run(&mut login, &mut scale),
        LoginStatus::Failed(LoginError::ProofMismatch)
    );
}

/// A refusing simulator answers the app proof with `23 00 00 00`.
#[test]
fn refusal() {
    let mut config = SimConfig::new(token(), [0x90; 16]);
    config.refuse_login = true;
    let mut scale = SimScale::new(config, &[]);
    let mut login = Login::new(&token(), [0xa8; 16]);
    assert_eq!(
        run(&mut login, &mut scale),
        LoginStatus::Failed(LoginError::Refused)
    );
    assert_eq!(scale.phase(), SimPhase::Failed, "simulator");
}
