#![feature(test)]
extern crate test;

use cipher::{block_decryptor_bench, block_encryptor_bench};
use lea::{Lea128, Lea192, Lea256};

block_encryptor_bench!(Key: Lea128, lea128_encrypt_block, lea128_encrypt_blocks);
block_decryptor_bench!(Key: Lea128, lea128_decrypt_block, lea128_decrypt_blocks);

block_encryptor_bench!(Key: Lea192, lea192_encrypt_block, lea192_encrypt_blocks);
block_decryptor_bench!(Key: Lea192, lea192_decrypt_block, lea192_decrypt_blocks);

block_encryptor_bench!(Key: Lea256, lea256_encrypt_block, lea256_encrypt_blocks);
block_decryptor_bench!(Key: Lea256, lea256_decrypt_block, lea256_decrypt_blocks);
