use cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use hex_literal::hex;
use lea::{Lea128, Lea192, Lea256};

// =============================================================================
// KS X 3246 specification test vectors (Appendix A)
// https://seed.kisa.or.kr/kisa/algorithm/EgovLeaInfo.do
// =============================================================================

/// LEA-128 test vector from KS X 3246 Appendix A
#[test]
fn lea128_ks_x_3246() {
    let key = hex!("0f1e2d3c4b5a69788796a5b4c3d2e1f0");
    let pt = hex!("101112131415161718191a1b1c1d1e1f");
    let ct = hex!("9fc84e3528c6c6185532c7a704648bfd");

    let c = Lea128::new_from_slice(&key).unwrap();

    let mut buf = Array::from(pt);
    c.encrypt_block(&mut buf);
    assert_eq!(&buf[..], &ct);
    c.decrypt_block(&mut buf);
    assert_eq!(&buf[..], &pt);
}

/// LEA-192 test vector from KS X 3246 Appendix A
#[test]
fn lea192_ks_x_3246() {
    let key = hex!("0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a59687");
    let pt = hex!("202122232425262728292a2b2c2d2e2f");
    let ct = hex!("6fb95e325aad1b878cdcf5357674c6f2");

    let c = Lea192::new_from_slice(&key).unwrap();

    let mut buf = Array::from(pt);
    c.encrypt_block(&mut buf);
    assert_eq!(&buf[..], &ct);
    c.decrypt_block(&mut buf);
    assert_eq!(&buf[..], &pt);
}

/// LEA-256 test vector from KS X 3246 Appendix A
#[test]
fn lea256_ks_x_3246() {
    let key = hex!("0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a5968778695a4b3c2d1e0f");
    let pt = hex!("303132333435363738393a3b3c3d3e3f");
    let ct = hex!("d651aff647b189c13a8900ca27f9e197");

    let c = Lea256::new_from_slice(&key).unwrap();

    let mut buf = Array::from(pt);
    c.encrypt_block(&mut buf);
    assert_eq!(&buf[..], &ct);
    c.decrypt_block(&mut buf);
    assert_eq!(&buf[..], &pt);
}

// =============================================================================
// Additional test vectors from Linux kernel (KCMVP Verification Criteria V3.0)
// https://lwn.net/Articles/933001/
// https://lore.kernel.org/linux-crypto/20231205010329.21996-3-letrehee@nsr.re.kr/
// =============================================================================

/// LEA-128 single-block vector #2 (from kernel testmgr.h)
#[test]
fn lea128_kernel_single() {
    let key = hex!("07ab6305b025d83f79addaa63ac8ad00");
    let pt = hex!("f28ae3256aad23b415e028063b610c60");
    let ct = hex!("64d908fcb7ebfef90fd670106de7c7c5");

    let c = Lea128::new_from_slice(&key).unwrap();

    let mut buf = Array::from(pt);
    c.encrypt_block(&mut buf);
    assert_eq!(&buf[..], &ct);
    c.decrypt_block(&mut buf);
    assert_eq!(&buf[..], &pt);
}

/// LEA-192 single-block vector #2 (from kernel testmgr.h)
#[test]
fn lea192_kernel_single() {
    let key = hex!("1437af533069bd7525c1560c78bad2a1e534671c007ef27c");
    let pt = hex!("1cb4f4cb6c4bdb5168ea8409727bfd51");
    let ct = hex!("69725c6df912f8b70eb511e6663c5870");

    let c = Lea192::new_from_slice(&key).unwrap();

    let mut buf = Array::from(pt);
    c.encrypt_block(&mut buf);
    assert_eq!(&buf[..], &ct);
    c.decrypt_block(&mut buf);
    assert_eq!(&buf[..], &pt);
}

/// LEA-256 single-block vector #2 (from kernel testmgr.h)
#[test]
fn lea256_kernel_single() {
    let key = hex!("4f6779e2bd1e9319c63015acffefd7a791f0ed59df1b700769fe82e2f0668c35");
    let pt = hex!("dc31cae3da5e0a11c966b020d7cffede");
    let ct = hex!("eda2042098f667e857a02db8caa7dff2");

    let c = Lea256::new_from_slice(&key).unwrap();

    let mut buf = Array::from(pt);
    c.encrypt_block(&mut buf);
    assert_eq!(&buf[..], &ct);
    c.decrypt_block(&mut buf);
    assert_eq!(&buf[..], &pt);
}

/// LEA-128 multi-block (5 blocks) from kernel testmgr.h
#[test]
fn lea128_kernel_5_blocks() {
    let key = hex!("42af3bcd6cbeaaeff1a7c26e61cd2bde");

    let pt_blocks: [[u8; 16]; 5] = [
        hex!("5183be45fd2047ce315189c269b483b3"),
        hex!("37a2f2fbe54c17655b09ba2944ee6f1e"),
        hex!("6da0182b6d66abfe8b823601dcc2208a"),
        hex!("ac52b1531fd4d42918b21ce85ab306a6"),
        hex!("eecd7e2fc43ba4b29dcfcfb92788d25e"),
    ];
    let ct_blocks: [[u8; 16]; 5] = [
        hex!("f3b6bf4afba7103e32b2ac2e7b46ff91"),
        hex!("e872bcbb93cf52e294ed5539871c4893"),
        hex!("d14c54088646e2fd0b7c62d583f3af67"),
        hex!("18b0ba83c7a29e2f962df06062121c52"),
        hex!("1bb9e76d7035070719edfb409c5b83c2"),
    ];

    let c = Lea128::new_from_slice(&key).unwrap();

    for (pt, ct) in pt_blocks.iter().zip(ct_blocks.iter()) {
        let mut buf = Array::from(*pt);
        c.encrypt_block(&mut buf);
        assert_eq!(&buf[..], ct);
        c.decrypt_block(&mut buf);
        assert_eq!(&buf[..], pt);
    }
}

/// LEA-192 multi-block (5 blocks) from kernel testmgr.h
#[test]
fn lea192_kernel_5_blocks() {
    let key = hex!("5edc346904b296cf6bf3b418e9ab35db0a47a11133a924ca");

    let pt_blocks: [[u8; 16]; 5] = [
        hex!("857c8f1f04c5a068f9bb83af95d99864"),
        hex!("d6317751af0332d1638eda3d322644a8"),
        hex!("37870ccc9169db43c155e6fb53b6b7e4"),
        hex!("c13330eb943ccd2ccce3296382eec4a4"),
        hex!("cc2a034de10278387d4f643587727ab7"),
    ];
    let ct_blocks: [[u8; 16]; 5] = [
        hex!("72223a93942f7359fe5e516a05c8e841"),
        hex!("c59bb74714809b13a9757b8293f9b0b4"),
        hex!("20d1c5a4f440f365d08f9425e347b5dd"),
        hex!("23a9ed05f2ce1618ccb09e712c59b97b"),
        hex!("7674517fc875ae9f6f188bfa5a42bac9"),
    ];

    let c = Lea192::new_from_slice(&key).unwrap();

    for (pt, ct) in pt_blocks.iter().zip(ct_blocks.iter()) {
        let mut buf = Array::from(*pt);
        c.encrypt_block(&mut buf);
        assert_eq!(&buf[..], ct);
        c.decrypt_block(&mut buf);
        assert_eq!(&buf[..], pt);
    }
}

/// LEA-256 multi-block (5 blocks) from kernel testmgr.h
#[test]
fn lea256_kernel_5_blocks() {
    let key = hex!("909809cb3809bcddb99a083d12617bcaf7530645735abc04d2a8d7eabe4afc96");

    let pt_blocks: [[u8; 16]; 5] = [
        hex!("a800c0db6a4c6a702ac9fae981be6be6"),
        hex!("dcf3368b23c317309973135904c2bae8"),
        hex!("0dc1aa91e9e5548f395b03952f9b1a08"),
        hex!("f3409c6b4517f21b6376e93c2dcffbf3"),
        hex!("8784cfd5fffd03a0b0f9282965210e96"),
    ];
    let ct_blocks: [[u8; 16]; 5] = [
        hex!("2a50fa90ed00ebfa1188cc9113dd4337"),
        hex!("b380d5f8c1582c8077ec6728ec318ab4"),
        hex!("5de5efd1d0a62e4e870352832bec223d"),
        hex!("8d5dcd397209c824e4a957f65d785ba5"),
        hex!("d7f9a4cc5d0b353528dbcca63548668a"),
    ];

    let c = Lea256::new_from_slice(&key).unwrap();

    for (pt, ct) in pt_blocks.iter().zip(ct_blocks.iter()) {
        let mut buf = Array::from(*pt);
        c.encrypt_block(&mut buf);
        assert_eq!(&buf[..], ct);
        c.decrypt_block(&mut buf);
        assert_eq!(&buf[..], pt);
    }
}

// =============================================================================
// KISA official LEA-128 ECB KAT vectors (LEA-128_(ECB)_KAT.txt)
// https://seed.kisa.or.kr/kisa/kcmvp/EgovVerification.do
// =============================================================================

/// First varying-PT vector: KEY=0, PT=80000000..., CT=CE8DCF04...
#[test]
fn lea128_kisa_kat_varying_pt_first() {
    let key = hex!("00000000000000000000000000000000");
    let pt = hex!("80000000000000000000000000000000");
    let ct = hex!("CE8DCF04DD60982B1D8F5035FD534DE2");

    let c = Lea128::new_from_slice(&key).unwrap();

    let mut buf = Array::from(pt);
    c.encrypt_block(&mut buf);
    assert_eq!(&buf[..], &ct);
    c.decrypt_block(&mut buf);
    assert_eq!(&buf[..], &pt);
}

/// Last varying-PT vector (vector 128): KEY=0, PT=FF...FF, CT=5311E9CF...
#[test]
fn lea128_kisa_kat_varying_pt_last() {
    let key = hex!("00000000000000000000000000000000");
    let pt = hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    let ct = hex!("5311E9CF5A38D30FFAB396F4BEFD4A62");

    let c = Lea128::new_from_slice(&key).unwrap();

    let mut buf = Array::from(pt);
    c.encrypt_block(&mut buf);
    assert_eq!(&buf[..], &ct);
    c.decrypt_block(&mut buf);
    assert_eq!(&buf[..], &pt);
}

/// First varying-KEY vector: KEY=80000000..., PT=0, CT=4D83E55D...
#[test]
fn lea128_kisa_kat_varying_key_first() {
    let key = hex!("80000000000000000000000000000000");
    let pt = hex!("00000000000000000000000000000000");
    let ct = hex!("4D83E55D4BA87093B609C574E4F65A23");

    let c = Lea128::new_from_slice(&key).unwrap();

    let mut buf = Array::from(pt);
    c.encrypt_block(&mut buf);
    assert_eq!(&buf[..], &ct);
    c.decrypt_block(&mut buf);
    assert_eq!(&buf[..], &pt);
}

/// Last varying-KEY vector: KEY=FF...FF, PT=0, CT=35760B28...
#[test]
fn lea128_kisa_kat_varying_key_last() {
    let key = hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    let pt = hex!("00000000000000000000000000000000");
    let ct = hex!("35760B28A6575BFC90408A80872B0BB2");

    let c = Lea128::new_from_slice(&key).unwrap();

    let mut buf = Array::from(pt);
    c.encrypt_block(&mut buf);
    assert_eq!(&buf[..], &ct);
    c.decrypt_block(&mut buf);
    assert_eq!(&buf[..], &pt);
}

/// Last random vector: KEY=0, PT=793AB7F5..., CT=F7989B6E...
#[test]
fn lea128_kisa_kat_random_last() {
    let key = hex!("00000000000000000000000000000000");
    let pt = hex!("793AB7F54E7CF765AB9C302B4451D050");
    let ct = hex!("F7989B6E61EA42005D9F13D9AE6E7207");

    let c = Lea128::new_from_slice(&key).unwrap();

    let mut buf = Array::from(pt);
    c.encrypt_block(&mut buf);
    assert_eq!(&buf[..], &ct);
    c.decrypt_block(&mut buf);
    assert_eq!(&buf[..], &pt);
}
