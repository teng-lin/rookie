//! The Secret Service DH protocol uses the first 16 bytes of HKDF-SHA256 with
//! empty salt and info. RustCrypto's `hkdf`/`hmac` 0.12 contexts do not
//! implement `Zeroize`, so this deliberately small implementation keeps every
//! keyed SHA/HMAC state and message block in `Zeroizing` storage.

use zeroize::{Zeroize, Zeroizing};

const SHA256_INITIAL_STATE: [u32; 8] = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const SHA256_ROUND_CONSTANTS: [u32; 64] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

struct Sha256 {
  state: Zeroizing<[u32; 8]>,
  block: Zeroizing<[u8; 64]>,
  block_len: usize,
  message_len: u64,
}

impl Sha256 {
  fn new() -> Self {
    Self {
      state: Zeroizing::new(SHA256_INITIAL_STATE),
      block: Zeroizing::new([0; 64]),
      block_len: 0,
      message_len: 0,
    }
  }

  fn update(&mut self, mut input: &[u8]) {
    self.message_len = self
      .message_len
      .checked_add(input.len() as u64)
      .expect("Secret Service HKDF input length fits u64");
    while !input.is_empty() {
      let copied = (64 - self.block_len).min(input.len());
      self.block[self.block_len..self.block_len + copied].copy_from_slice(&input[..copied]);
      self.block_len += copied;
      input = &input[copied..];
      if self.block_len == 64 {
        self.compress();
        self.block.zeroize();
        self.block_len = 0;
      }
    }
  }

  fn finalize(mut self) -> Zeroizing<[u8; 32]> {
    let bit_len = self
      .message_len
      .checked_mul(8)
      .expect("Secret Service HKDF bit length fits u64");
    self.block[self.block_len] = 0x80;
    self.block_len += 1;
    if self.block_len > 56 {
      self.block[self.block_len..].fill(0);
      self.compress();
      self.block.zeroize();
      self.block_len = 0;
    }
    self.block[self.block_len..56].fill(0);
    self.block[56..].copy_from_slice(&bit_len.to_be_bytes());
    self.compress();

    let mut digest = Zeroizing::new([0_u8; 32]);
    for (output, word) in digest
      .as_chunks_mut::<4>()
      .0
      .iter_mut()
      .zip(self.state.iter())
    {
      output.copy_from_slice(&word.to_be_bytes());
    }
    digest
  }

  fn compress(&mut self) {
    let mut schedule = Zeroizing::new([0_u32; 64]);
    for (word, bytes) in schedule[..16].iter_mut().zip(self.block.as_chunks::<4>().0) {
      *word = u32::from_be_bytes(*bytes);
    }
    for index in 16..64 {
      let s0 = schedule[index - 15].rotate_right(7)
        ^ schedule[index - 15].rotate_right(18)
        ^ (schedule[index - 15] >> 3);
      let s1 = schedule[index - 2].rotate_right(17)
        ^ schedule[index - 2].rotate_right(19)
        ^ (schedule[index - 2] >> 10);
      schedule[index] = schedule[index - 16]
        .wrapping_add(s0)
        .wrapping_add(schedule[index - 7])
        .wrapping_add(s1);
    }

    let mut working = Zeroizing::new(*self.state);
    let mut temporary1 = 0_u32;
    let mut temporary2 = 0_u32;
    for index in 0..64 {
      let big_sigma1 =
        working[4].rotate_right(6) ^ working[4].rotate_right(11) ^ working[4].rotate_right(25);
      let choice = (working[4] & working[5]) ^ (!working[4] & working[6]);
      temporary1 = working[7]
        .wrapping_add(big_sigma1)
        .wrapping_add(choice)
        .wrapping_add(SHA256_ROUND_CONSTANTS[index])
        .wrapping_add(schedule[index]);
      let big_sigma0 =
        working[0].rotate_right(2) ^ working[0].rotate_right(13) ^ working[0].rotate_right(22);
      let majority =
        (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
      temporary2 = big_sigma0.wrapping_add(majority);
      working.copy_within(0..7, 1);
      working[4] = working[4].wrapping_add(temporary1);
      working[0] = temporary1.wrapping_add(temporary2);
    }
    for (state, word) in self.state.iter_mut().zip(working.iter()) {
      *state = state.wrapping_add(*word);
    }
    temporary1.zeroize();
    temporary2.zeroize();
  }
}

fn hmac_sha256(key: &[u8], messages: &[&[u8]]) -> Zeroizing<[u8; 32]> {
  assert!(
    key.len() <= 64,
    "Secret Service HKDF HMAC key fits one block"
  );
  let mut key_block = Zeroizing::new([0_u8; 64]);
  key_block[..key.len()].copy_from_slice(key);
  let mut inner_pad = Zeroizing::new([0_u8; 64]);
  let mut outer_pad = Zeroizing::new([0_u8; 64]);
  for index in 0..64 {
    inner_pad[index] = key_block[index] ^ 0x36;
    outer_pad[index] = key_block[index] ^ 0x5c;
  }

  let mut inner = Sha256::new();
  inner.update(inner_pad.as_ref());
  for message in messages {
    inner.update(message);
  }
  let inner_digest = inner.finalize();
  let mut outer = Sha256::new();
  outer.update(outer_pad.as_ref());
  outer.update(inner_digest.as_ref());
  outer.finalize()
}

pub(super) fn derive_aes128_key(input_key_material: &[u8]) -> Zeroizing<[u8; 16]> {
  let salt = Zeroizing::new([0_u8; 32]);
  let pseudorandom_key = hmac_sha256(salt.as_ref(), &[input_key_material]);
  let counter = Zeroizing::new([1_u8]);
  let output_block = hmac_sha256(pseudorandom_key.as_ref(), &[counter.as_ref()]);
  let mut aes_key = Zeroizing::new([0_u8; 16]);
  aes_key.copy_from_slice(&output_block[..16]);
  aes_key
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn sha256_matches_the_nist_abc_vector() {
    let mut hash = Sha256::new();
    hash.update(b"abc");
    assert_eq!(
      hash.finalize().as_ref(),
      [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
      ]
    );
  }

  #[test]
  fn hmac_sha256_matches_rfc4231_case_one() {
    let key = Zeroizing::new([0x0b; 20]);
    assert_eq!(
      hmac_sha256(key.as_ref(), &[b"Hi There"]).as_ref(),
      [
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1,
        0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32,
        0xcf, 0xf7,
      ]
    );
  }

  #[test]
  fn extract_and_expand_match_rfc5869_case_one() {
    let input_key_material = Zeroizing::new([0x0b; 22]);
    let salt = Zeroizing::new([
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ]);
    let info = Zeroizing::new([0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9]);
    let pseudorandom_key = hmac_sha256(salt.as_ref(), &[input_key_material.as_ref()]);
    assert_eq!(
      pseudorandom_key.as_ref(),
      [
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba,
        0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2,
        0xb3, 0xe5,
      ]
    );

    let counter_one = Zeroizing::new([1_u8]);
    let first = hmac_sha256(
      pseudorandom_key.as_ref(),
      &[info.as_ref(), counter_one.as_ref()],
    );
    let counter_two = Zeroizing::new([2_u8]);
    let second = hmac_sha256(
      pseudorandom_key.as_ref(),
      &[first.as_ref(), info.as_ref(), counter_two.as_ref()],
    );
    let mut output = Zeroizing::new([0_u8; 42]);
    output[..32].copy_from_slice(first.as_ref());
    output[32..].copy_from_slice(&second[..10]);
    assert_eq!(
      output.as_ref(),
      [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f,
        0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4,
        0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
      ]
    );
  }

  #[test]
  fn empty_salt_and_info_match_an_independent_hkdf_sha256_vector() {
    let input = Zeroizing::new(std::array::from_fn::<_, 128, _>(|index| index as u8));
    let key = derive_aes128_key(input.as_ref());
    assert_eq!(
      key.as_ref(),
      [
        0xd0, 0x30, 0xa0, 0x65, 0xc4, 0xf9, 0x92, 0x45, 0x75, 0x6b, 0x6f, 0xc3, 0x0d, 0x00, 0xa2,
        0x94,
      ]
    );
  }
}
