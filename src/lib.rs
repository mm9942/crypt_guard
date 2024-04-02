mod Core;
/// Cryptographic related functionalitys, enums structs and modules
mod cryptography;
mod KeyControl;
pub mod error;
#[cfg(test)]
mod tests;

pub use crate::{
    KeyControl::{
        *,
        file::*, 
    },
    Core::{
        *,
        kyber::{
            *,
            KeyKyber::{self, *},
        },
    },
    cryptography::{
        *,
        signature::{
            sign_falcon::*,
            sign_dilithium::*
        },
    }

};

use KeyControl::*;
use cryptography::*;


use pqcrypto_falcon::falcon1024::{self, *};
use pqcrypto_kyber::kyber1024::{self, *};
use std::{
    error::Error,
    fmt::{self, *},
    io,
};