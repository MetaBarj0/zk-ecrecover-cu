use dep::ecrecover;

fn main(
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],
    hashed_message: [u8; 32],
    expected_address: Field,
) {
    let mut s: [u8; 32] = [0; 32];

    for i in 0..32 {
        s[i] = signature[i + 32];
    }

    // secp256k1 half order: 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
    let half_order: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];

    // Check that s <= half_order to prevent signature malleability
    let s_is_canonical = is_less_than_or_equal(s, half_order);
    assert(s_is_canonical, "signature malleability vulnerability uncovered");

    let address = ecrecover::ecrecover(pub_key_x, pub_key_y, signature, hashed_message);

    assert(address != 0x00, "zero address recovered");
    assert(address == expected_address, "address is not the expected one");
}

// Helper function to compare two 32-byte arrays (big-endian)
fn is_less_than_or_equal(a: [u8; 32], b: [u8; 32]) -> bool {
    let mut res: bool = false;
    let mut stop: bool = false;

    for i in 0..32 {
        if !stop {
            if a[i] < b[i] {
                res = true;
                stop = true;
            } else if a[i] > b[i] {
                res = false;
                stop = true;
            }
        }
    }
    res
}
