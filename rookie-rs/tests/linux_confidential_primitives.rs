#![allow(unknown_lints)]
#![allow(clippy::chunks_exact_to_as_chunks)]

// Exercise the platform-independent confidential-session primitives on every
// host, including CI runners that cannot execute a Linux target binary.
#[path = "../src/linux/zeroizing_dh.rs"]
mod zeroizing_dh;

#[path = "../src/linux/zeroizing_hkdf.rs"]
mod zeroizing_hkdf;

#[test]
fn shared_secret_hkdf_uses_the_gnome_prime_width_encoding() {
  use sha2::{Digest, Sha256};

  let private_key = [0x42; zeroizing_dh::KEY_BYTES];
  // 2^231 is a valid peer key whose shared result is only 1016 bits, making
  // the otherwise easy-to-miss leading-zero convention observable.
  let mut peer_public_key = [0_u8; 29];
  peer_public_key[0] = 0x80;
  let shared = zeroizing_dh::shared_secret(&peer_public_key, &private_key)
    .expect("2^231 is a valid MODP peer public key");

  assert_eq!(shared.len(), zeroizing_dh::KEY_BYTES);
  assert_eq!(shared[0], 0);
  assert_eq!(
    Sha256::digest(shared.as_ref()).as_slice(),
    [
      0x36, 0x92, 0x0f, 0x95, 0x65, 0x9b, 0x6d, 0x26, 0xcc, 0x4d, 0x9d, 0xdf, 0xb8, 0xc5, 0x47,
      0x17, 0xd2, 0xce, 0x88, 0xe0, 0x1f, 0xf1, 0xc0, 0x82, 0xc3, 0x76, 0xe5, 0x14, 0xc8, 0x65,
      0xe8, 0xe4,
    ]
  );

  let fixed_width_key = zeroizing_hkdf::derive_aes128_key(shared.as_ref());
  assert_eq!(
    fixed_width_key.as_ref(),
    [
      0x22, 0x32, 0xfb, 0x74, 0x1a, 0xd0, 0xd8, 0x76, 0x6d, 0x59, 0x03, 0xac, 0xcf, 0xe5, 0xa1,
      0xff,
    ]
  );

  let minimal_mpi_key = zeroizing_hkdf::derive_aes128_key(&shared[1..]);
  assert_eq!(
    minimal_mpi_key.as_ref(),
    [
      0x5d, 0x21, 0x29, 0x0a, 0x2c, 0x23, 0x51, 0x79, 0x62, 0xab, 0xe3, 0x68, 0xa2, 0xfe, 0xd9,
      0x7b,
    ]
  );
  assert_ne!(fixed_width_key, minimal_mpi_key);
}
