use std::{
  cmp::Ordering,
  ops::{Deref, DerefMut},
};

use anyhow::{bail, Result};
use zeroize::{Zeroize, Zeroizing};

pub(super) const KEY_BYTES: usize = 128;
const WORDS: usize = KEY_BYTES / 4;
const PRODUCT_WORDS: usize = WORDS * 2 + 1;

// RFC 2409's 1024-bit MODP group, stored least-significant word first.
const MODULUS: [u32; WORDS] = [
  0xffff_ffff,
  0xffff_ffff,
  0xece6_5381,
  0x4928_6651,
  0x7c4b_1fe6,
  0xae9f_2411,
  0x5a89_9fa5,
  0xee38_6bfb,
  0xf406_b7ed,
  0x0bff_5cb6,
  0xa637_ed6b,
  0xf44c_42e9,
  0x625e_7ec6,
  0xe485_b576,
  0x6d51_c245,
  0x4fe1_356d,
  0xf25f_1437,
  0x302b_0a6d,
  0xcd3a_431b,
  0xef95_19b3,
  0x8e34_04dd,
  0x514a_0879,
  0x3b13_9b22,
  0x020b_bea6,
  0x8a67_cc74,
  0x2902_4e08,
  0x80dc_1cd1,
  0xc4c6_628b,
  0x2168_c234,
  0xc90f_daa2,
  0xffff_ffff,
  0xffff_ffff,
];

const MODULUS_MINUS_ONE: [u32; WORDS] = [
  0xffff_fffe,
  0xffff_ffff,
  0xece6_5381,
  0x4928_6651,
  0x7c4b_1fe6,
  0xae9f_2411,
  0x5a89_9fa5,
  0xee38_6bfb,
  0xf406_b7ed,
  0x0bff_5cb6,
  0xa637_ed6b,
  0xf44c_42e9,
  0x625e_7ec6,
  0xe485_b576,
  0x6d51_c245,
  0x4fe1_356d,
  0xf25f_1437,
  0x302b_0a6d,
  0xcd3a_431b,
  0xef95_19b3,
  0x8e34_04dd,
  0x514a_0879,
  0x3b13_9b22,
  0x020b_bea6,
  0x8a67_cc74,
  0x2902_4e08,
  0x80dc_1cd1,
  0xc4c6_628b,
  0x2168_c234,
  0xc90f_daa2,
  0xffff_ffff,
  0xffff_ffff,
];

/// Fixed-size arithmetic storage whose complete backing array is wiped before
/// it leaves scope. No heap-allocated bignum temporaries or power tables exist.
struct SecretWords<const N: usize> {
  words: [u32; N],
}

impl<const N: usize> SecretWords<N> {
  fn zeroed() -> Self {
    Self { words: [0; N] }
  }
}

impl<const N: usize> Deref for SecretWords<N> {
  type Target = [u32; N];

  fn deref(&self) -> &Self::Target {
    &self.words
  }
}

impl<const N: usize> DerefMut for SecretWords<N> {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.words
  }
}

impl<const N: usize> Drop for SecretWords<N> {
  fn drop(&mut self) {
    self.words.zeroize();
    #[cfg(test)]
    record_drop(N, &self.words);
  }
}

pub(super) fn public_key(private_key: &[u8; KEY_BYTES]) -> Vec<u8> {
  let mut generator = SecretWords::<WORDS>::zeroed();
  generator[0] = 2;
  let public = modpow(&generator, private_key);
  to_minimal_be(&public)
}

pub(super) fn shared_secret(
  encoded_peer_key: &[u8],
  private_key: &[u8; KEY_BYTES],
) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
  let peer_key = parse_peer_key(encoded_peer_key)?;
  let shared = modpow(&peer_key, private_key);
  // Modern GNOME libsecret and gnome-keyring normalize the DH result to the
  // MODP prime width before HKDF: both libsecret crypto backends right-align
  // the integer in a prime-sized zero-filled buffer. A minimal MPI here
  // derives a different AES key whenever the shared value has a leading zero.
  Ok(to_fixed_be(&shared))
}

fn parse_peer_key(encoded: &[u8]) -> Result<SecretWords<WORDS>> {
  let key = from_be(encoded)?;
  let mut two = SecretWords::<WORDS>::zeroed();
  two[0] = 2;
  if compare(&key, &two) == Ordering::Less || compare(&key, &MODULUS_MINUS_ONE) != Ordering::Less {
    bail!("Secret Service confidential-session negotiation returned an invalid public key");
  }
  Ok(key)
}

fn from_be(encoded: &[u8]) -> Result<SecretWords<WORDS>> {
  let significant = if encoded.len() > KEY_BYTES {
    let (prefix, significant) = encoded.split_at(encoded.len() - KEY_BYTES);
    if prefix.iter().any(|byte| *byte != 0) {
      bail!("Secret Service confidential-session public key exceeds the DH group size");
    }
    significant
  } else {
    encoded
  };

  let mut result = SecretWords::<WORDS>::zeroed();
  for (word_index, chunk) in significant.rchunks(4).enumerate() {
    let mut word = 0_u32;
    for byte in chunk {
      word = (word << 8) | u32::from(*byte);
    }
    result[word_index] = word;
    word.zeroize();
  }
  Ok(result)
}

fn to_fixed_be(value: &SecretWords<WORDS>) -> Zeroizing<[u8; KEY_BYTES]> {
  let mut result = Zeroizing::new([0_u8; KEY_BYTES]);
  for (index, word) in value.iter().enumerate() {
    let offset = KEY_BYTES - (index + 1) * 4;
    let mut encoded_word = *word;
    result[offset] = (encoded_word >> 24) as u8;
    result[offset + 1] = (encoded_word >> 16) as u8;
    result[offset + 2] = (encoded_word >> 8) as u8;
    result[offset + 3] = encoded_word as u8;
    encoded_word.zeroize();
  }
  result
}

fn to_minimal_be(value: &SecretWords<WORDS>) -> Vec<u8> {
  let fixed = to_fixed_be(value);
  let first = fixed
    .iter()
    .position(|byte| *byte != 0)
    .unwrap_or(KEY_BYTES - 1);
  fixed[first..].to_vec()
}

fn compare(left: &[u32; WORDS], right: &[u32; WORDS]) -> Ordering {
  for index in (0..WORDS).rev() {
    match left[index].cmp(&right[index]) {
      Ordering::Equal => {}
      ordering => return ordering,
    }
  }
  Ordering::Equal
}

fn subtract_modulus(value: &[u32; WORDS]) -> (SecretWords<WORDS>, Zeroizing<u32>) {
  let mut result = SecretWords::<WORDS>::zeroed();
  let mut borrow = 0_u64;
  let mut subtrahend = 0_u64;
  let mut current = 0_u64;
  for index in 0..WORDS {
    subtrahend = u64::from(MODULUS[index]) + borrow;
    current = u64::from(value[index]);
    result[index] = current.wrapping_sub(subtrahend) as u32;
    borrow = u64::from(current < subtrahend);
  }
  let final_borrow = Zeroizing::new(borrow as u32);
  borrow.zeroize();
  subtrahend.zeroize();
  current.zeroize();
  (result, final_borrow)
}

fn select_words(
  zero_choice: &[u32; WORDS],
  one_choice: &[u32; WORDS],
  mut choice: u32,
) -> SecretWords<WORDS> {
  let mut mask = 0_u32.wrapping_sub(choice);
  let mut inverse_mask = !mask;
  let mut result = SecretWords::<WORDS>::zeroed();
  for index in 0..WORDS {
    result[index] = (zero_choice[index] & inverse_mask) | (one_choice[index] & mask);
  }
  mask.zeroize();
  inverse_mask.zeroize();
  choice.zeroize();
  result
}

fn add_mod(left: &[u32; WORDS], right: &[u32; WORDS]) -> SecretWords<WORDS> {
  let mut result = SecretWords::<WORDS>::zeroed();
  let mut carry = 0_u64;
  let mut total = 0_u64;
  for index in 0..WORDS {
    total = u64::from(left[index]) + u64::from(right[index]) + carry;
    result[index] = total as u32;
    carry = total >> 32;
  }
  let (reduced, mut borrow) = subtract_modulus(&result);
  let mut carry_bit = carry as u32;
  let mut select_reduced = carry_bit | (*borrow ^ 1);
  result = select_words(&result, &reduced, select_reduced);
  borrow.zeroize();
  carry_bit.zeroize();
  select_reduced.zeroize();
  carry.zeroize();
  total.zeroize();
  result
}

fn to_montgomery(value: &[u32; WORDS]) -> SecretWords<WORDS> {
  // R = 2^1024. Repeated modular doubling avoids embedding another large
  // derived constant and keeps every intermediate in SecretWords.
  let mut result = SecretWords::<WORDS>::zeroed();
  result.copy_from_slice(value);
  for _ in 0..(WORDS * 32) {
    result = add_mod(&result, &result);
  }
  result
}

fn montgomery_multiply(left: &[u32; WORDS], right: &[u32; WORDS]) -> SecretWords<WORDS> {
  let mut workspace = SecretWords::<PRODUCT_WORDS>::zeroed();
  let mut carry = 0_u64;
  let mut total = 0_u64;

  for (left_index, left_word) in left.iter().enumerate() {
    carry = 0;
    for (right_index, right_word) in right.iter().enumerate() {
      let index = left_index + right_index;
      total = u64::from(workspace[index]) + u64::from(*left_word) * u64::from(*right_word) + carry;
      workspace[index] = total as u32;
      carry = total >> 32;
    }
    for index in left_index + WORDS..PRODUCT_WORDS {
      total = u64::from(workspace[index]) + carry;
      workspace[index] = total as u32;
      carry = total >> 32;
    }
  }

  // MODULUS[0] is -1 mod 2^32, so -MODULUS[0]^-1 is exactly one.
  // This is the word-at-a-time Montgomery REDC algorithm.
  let mut multiplier = 0_u32;
  for offset in 0..WORDS {
    multiplier = workspace[offset];
    carry = 0;
    for (modulus_index, modulus_word) in MODULUS.iter().enumerate() {
      let index = offset + modulus_index;
      total =
        u64::from(workspace[index]) + u64::from(multiplier) * u64::from(*modulus_word) + carry;
      workspace[index] = total as u32;
      carry = total >> 32;
    }
    for index in offset + WORDS..PRODUCT_WORDS {
      total = u64::from(workspace[index]) + carry;
      workspace[index] = total as u32;
      carry = total >> 32;
    }
  }

  let mut result = SecretWords::<WORDS>::zeroed();
  result.copy_from_slice(&workspace[WORDS..WORDS * 2]);
  let (reduced, mut borrow) = subtract_modulus(&result);
  let mut high = workspace[WORDS * 2];
  let mut high_is_nonzero = (high | high.wrapping_neg()) >> 31;
  let mut select_reduced = high_is_nonzero | (*borrow ^ 1);
  result = select_words(&result, &reduced, select_reduced);

  multiplier.zeroize();
  borrow.zeroize();
  high.zeroize();
  high_is_nonzero.zeroize();
  select_reduced.zeroize();
  carry.zeroize();
  total.zeroize();
  result
}

fn modpow(base: &[u32; WORDS], exponent: &[u8; KEY_BYTES]) -> SecretWords<WORDS> {
  let base = to_montgomery(base);
  let mut one = SecretWords::<WORDS>::zeroed();
  one[0] = 1;
  let mut result = to_montgomery(&one);
  let mut bit = 0_u32;

  for exponent_byte in exponent {
    for bit_index in (0..8).rev() {
      let squared = montgomery_multiply(&result, &result);
      let multiplied = montgomery_multiply(&squared, &base);
      bit = u32::from((*exponent_byte >> bit_index) & 1);
      result = select_words(&squared, &multiplied, bit);
      bit.zeroize();
    }
  }

  bit.zeroize();
  montgomery_multiply(&result, &one)
}

#[cfg(test)]
type DropObservation = (usize, Vec<u32>);

#[cfg(test)]
thread_local! {
  static DROP_OBSERVATIONS: std::cell::RefCell<Option<Vec<DropObservation>>> = const {
    std::cell::RefCell::new(None)
  };
}

#[cfg(test)]
fn record_drop(word_count: usize, wiped: &[u32]) {
  DROP_OBSERVATIONS.with(|observations| {
    if let Some(observations) = observations.borrow_mut().as_mut() {
      observations.push((word_count, wiped.to_vec()));
    }
  });
}

#[cfg(test)]
mod tests {
  use super::*;
  use sha2::{Digest, Sha256};

  type ReferenceWords = [u32; WORDS + 1];

  fn decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
      .step_by(2)
      .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("valid hex"))
      .collect()
  }

  fn observe_drops(test: impl FnOnce()) -> Vec<DropObservation> {
    DROP_OBSERVATIONS.with(|observations| {
      assert!(observations.borrow().is_none());
      *observations.borrow_mut() = Some(Vec::new());
    });
    test();
    DROP_OBSERVATIONS.with(|observations| {
      observations
        .borrow_mut()
        .take()
        .expect("drop observations enabled")
    })
  }

  fn reference_compare(left: &ReferenceWords, right: &ReferenceWords) -> Ordering {
    for index in (0..=WORDS).rev() {
      match left[index].cmp(&right[index]) {
        Ordering::Equal => {}
        ordering => return ordering,
      }
    }
    Ordering::Equal
  }

  fn reference_modulus() -> ReferenceWords {
    let mut modulus = [0_u32; WORDS + 1];
    modulus[..WORDS].copy_from_slice(&MODULUS);
    modulus
  }

  fn reference_subtract(left: &mut ReferenceWords, right: &ReferenceWords) {
    let mut borrow = 0_u64;
    for index in 0..=WORDS {
      let subtrahend = u64::from(right[index]) + borrow;
      let current = u64::from(left[index]);
      left[index] = current.wrapping_sub(subtrahend) as u32;
      borrow = u64::from(current < subtrahend);
    }
    assert_eq!(borrow, 0);
  }

  fn reference_add_mod(left: &ReferenceWords, right: &ReferenceWords) -> ReferenceWords {
    let modulus = reference_modulus();
    let mut result = [0_u32; WORDS + 1];
    let mut carry = 0_u64;
    for index in 0..=WORDS {
      let total = u64::from(left[index]) + u64::from(right[index]) + carry;
      result[index] = total as u32;
      carry = total >> 32;
    }
    assert_eq!(carry, 0);
    if reference_compare(&result, &modulus) != Ordering::Less {
      reference_subtract(&mut result, &modulus);
    }
    result
  }

  fn as_reference(value: &[u32; WORDS]) -> ReferenceWords {
    let mut result = [0_u32; WORDS + 1];
    result[..WORDS].copy_from_slice(value);
    result
  }

  fn reference_multiply(left: &[u32; WORDS], right: &[u32; WORDS]) -> [u32; WORDS] {
    // Independent shift-and-add modular multiplication. This deliberately
    // shares neither Montgomery representation nor production helpers.
    let left = as_reference(left);
    let mut result = [0_u32; WORDS + 1];
    for word_index in (0..WORDS).rev() {
      for bit_index in (0..32).rev() {
        result = reference_add_mod(&result, &result);
        if (right[word_index] >> bit_index) & 1 != 0 {
          result = reference_add_mod(&result, &left);
        }
      }
    }
    let mut truncated = [0_u32; WORDS];
    truncated.copy_from_slice(&result[..WORDS]);
    truncated
  }

  fn reference_modpow(base: &[u32; WORDS], exponent: &[u8; KEY_BYTES]) -> [u32; WORDS] {
    let mut result = [0_u32; WORDS];
    result[0] = 1;
    for byte in exponent {
      for bit_index in (0..8).rev() {
        result = reference_multiply(&result, &result);
        if (byte >> bit_index) & 1 != 0 {
          result = reference_multiply(&result, base);
        }
      }
    }
    result
  }

  fn decoded_montgomery_product(left: &[u32; WORDS], right: &[u32; WORDS]) -> SecretWords<WORDS> {
    let left = to_montgomery(left);
    let right = to_montgomery(right);
    let product = montgomery_multiply(&left, &right);
    let mut one = SecretWords::<WORDS>::zeroed();
    one[0] = 1;
    montgomery_multiply(&product, &one)
  }

  fn next_word(state: &mut u64) -> u32 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state as u32
  }

  #[test]
  fn fixed_width_dh_matches_independent_modular_exponentiation_vectors() {
    let private_key = [0x42; KEY_BYTES];
    let public = public_key(&private_key);
    let expected_public = decode(concat!(
      "efeedfe6b21cae4d2fa21e68011ac68cba9076cc29573375c4d40d77cd513bcb",
      "6e6c116253e417aed8fa60f07cd10bbfc97461c8dd5af396bb2b202834ff8570",
      "c54e896481e790eff259b430ebd8621c233b9073d4d57ec27a13be3599cf4b4",
      "1963c70ca43b0696a56efb1fd13bd8e71b60e9ef72bd890540228cb9f95e9f2b7",
    ));
    assert_eq!(public, expected_public);
    assert_eq!(
      Sha256::digest(&public).as_slice(),
      decode("27f58859f483e9ff66d071f72ca594c0992c9aba68c5235ee65f2e36cc634805")
    );

    // The peer exponent is 0x25, so its public value is 2^37.
    let shared = shared_secret(&[0x20, 0, 0, 0, 0], &private_key).expect("valid peer key");
    assert_eq!(
      shared.as_ref(),
      decode(concat!(
        "3cd7d5716a66e75dbb84e9f68df4cb78a31d907a9ef43b2cecf4d67c45781a78",
        "6ab37f5005318bc30be188085cedf32603363c58648ecb55ceaa551853907deb2",
        "3c1ecc1a22ed23f9f7ae0ced524235f48418f728e734df4be5cacdf268b0156a",
        "4f7e4a51fcb52b9186c013a3598434cb5710eb2192815552505086f76599854",
      ))
    );
    assert_eq!(
      Sha256::digest(shared.as_ref()).as_slice(),
      decode("378321ba3204a71dc29b24215f84dd3cdfd450728ca44a5287887dc1ae0a69a4")
    );
  }

  #[test]
  fn fixed_width_encoding_preserves_minimal_public_and_padded_shared_values() {
    let mut exponent_zero = [0_u8; KEY_BYTES];
    let mut exponent_one = [0_u8; KEY_BYTES];
    exponent_one[KEY_BYTES - 1] = 1;
    let mut generator = SecretWords::<WORDS>::zeroed();
    generator[0] = 2;

    let power_zero = modpow(&generator, &exponent_zero);
    let power_one = modpow(&generator, &exponent_one);
    assert_eq!(to_minimal_be(&power_zero), [1]);
    assert_eq!(to_minimal_be(&power_one), [2]);
    assert_eq!(public_key(&exponent_one), [2]);

    let shared = shared_secret(&[2], &exponent_one).expect("generator is a valid peer key");
    assert!(shared[..KEY_BYTES - 1].iter().all(|byte| *byte == 0));
    assert_eq!(shared[KEY_BYTES - 1], 2);
    exponent_zero.zeroize();
    exponent_one.zeroize();
  }

  #[test]
  fn montgomery_products_cover_zero_one_and_modulus_boundaries() {
    let zero = [0_u32; WORDS];
    let mut one = [0_u32; WORDS];
    one[0] = 1;
    assert_eq!(decoded_montgomery_product(&zero, &zero).as_slice(), zero);
    assert_eq!(decoded_montgomery_product(&one, &one).as_slice(), one);
    assert_eq!(
      decoded_montgomery_product(&MODULUS_MINUS_ONE, &one).as_slice(),
      MODULUS_MINUS_ONE
    );
    assert_eq!(
      decoded_montgomery_product(&MODULUS_MINUS_ONE, &MODULUS_MINUS_ONE).as_slice(),
      one
    );
  }

  #[test]
  fn montgomery_products_match_independent_shift_and_add_arithmetic() {
    let mut state = 0x4d59_5df4_d0f3_3173_u64;
    for _ in 0..16 {
      let mut left = [0_u32; WORDS];
      let mut right = [0_u32; WORDS];
      for word in &mut left {
        *word = next_word(&mut state);
      }
      for word in &mut right {
        *word = next_word(&mut state);
      }
      if compare(&left, &MODULUS) != Ordering::Less {
        let (reduced, borrow) = subtract_modulus(&left);
        assert_eq!(*borrow, 0);
        left.copy_from_slice(reduced.as_slice());
      }
      if compare(&right, &MODULUS) != Ordering::Less {
        let (reduced, borrow) = subtract_modulus(&right);
        assert_eq!(*borrow, 0);
        right.copy_from_slice(reduced.as_slice());
      }
      assert_eq!(
        decoded_montgomery_product(&left, &right).as_slice(),
        reference_multiply(&left, &right)
      );
    }
  }

  #[test]
  fn modular_exponentiation_matches_independent_reference_cases() {
    let mut state = 0xa076_1d64_78bd_642f_u64;
    for _ in 0..3 {
      let mut base = [0_u32; WORDS];
      for word in &mut base {
        *word = next_word(&mut state);
      }
      if compare(&base, &MODULUS) != Ordering::Less {
        let (reduced, borrow) = subtract_modulus(&base);
        assert_eq!(*borrow, 0);
        base.copy_from_slice(reduced.as_slice());
      }
      let mut exponent = [0_u8; KEY_BYTES];
      for chunk in exponent[KEY_BYTES - 8..].chunks_exact_mut(4) {
        chunk.copy_from_slice(&next_word(&mut state).to_be_bytes());
      }
      assert_eq!(
        modpow(&base, &exponent).as_slice(),
        reference_modpow(&base, &exponent)
      );
    }
  }

  #[test]
  fn peer_public_key_rejects_degenerate_group_boundaries() {
    let modulus = to_fixed_be(&SecretWords { words: MODULUS });
    let modulus_minus_one = to_fixed_be(&SecretWords {
      words: MODULUS_MINUS_ONE,
    });
    let mut modulus_plus_one_words = MODULUS;
    let mut carry = 1_u64;
    for word in &mut modulus_plus_one_words {
      let total = u64::from(*word) + carry;
      *word = total as u32;
      carry = total >> 32;
    }
    assert_eq!(carry, 0);
    let modulus_plus_one = to_fixed_be(&SecretWords {
      words: modulus_plus_one_words,
    });
    for invalid in [
      &[][..],
      &[0][..],
      &[1][..],
      modulus_minus_one.as_ref(),
      modulus.as_ref(),
      modulus_plus_one.as_ref(),
    ] {
      assert!(parse_peer_key(invalid).is_err());
    }
    let mut modulus_minus_two = MODULUS_MINUS_ONE;
    modulus_minus_two[0] -= 1;
    let modulus_minus_two = to_fixed_be(&SecretWords {
      words: modulus_minus_two,
    });
    assert!(parse_peer_key(modulus_minus_two.as_ref()).is_ok());
    assert!(parse_peer_key(&[2]).is_ok());
    let mut leading_zero_two = vec![0; KEY_BYTES + 1];
    leading_zero_two[KEY_BYTES] = 2;
    assert!(parse_peer_key(&leading_zero_two).is_ok());
    let mut oversized = vec![0; KEY_BYTES + 1];
    oversized[0] = 1;
    assert!(parse_peer_key(&oversized).is_err());
  }

  #[test]
  fn every_fixed_width_arithmetic_allocation_is_wiped_before_drop() {
    let observed = observe_drops(|| {
      let private_key = [0x42; KEY_BYTES];
      let shared = shared_secret(&[0x20, 0, 0, 0, 0], &private_key).expect("valid peer key");
      drop(shared);
    });

    assert!(observed.iter().any(|(words, _)| *words == WORDS));
    assert!(observed.iter().any(|(words, _)| *words == PRODUCT_WORDS));
    assert!(observed
      .iter()
      .all(|(words, wiped)| { wiped.len() == *words && wiped.iter().all(|word| *word == 0) }));
  }
}
