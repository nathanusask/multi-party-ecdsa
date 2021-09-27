use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::orchestrate::check_sig;
use curv::elliptic::curves::secp256_k1::{FE, GE, Secp256k1Scalar, Secp256k1Point};
use curv::BigInt;
use curv::arithmetic::Converter;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use std::ops::Mul;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;

fn main() {
    // let r_bn = BigInt::from_str_radix("c124b009daa979fe94bf646113a5f5f4a4d760028ba23c858246ded561a04bc8", 16).unwrap();
    // let s_bn = BigInt::from_str_radix("7b7804a30a14edccbc5b9c871690faa2631001ab12b1b63f19194dc9f6e88c7d", 16).unwrap();
    // let r = ECScalar::from(&r_bn);
    // let s = ECScalar::from(&s_bn);
    //
    // let message = &[22, 164, 188, 209, 101, 223, 168, 71, 107, 216, 106, 105, 9, 98, 57, 228, 111, 6, 41, 205, 182, 196, 11, 47, 118, 73, 120, 181, 229, 70, 227, 237];
    // let message_bn = HSha256::create_hash(&[&BigInt::from_bytes(message)]);

    // // pk from keygen
    // let x_bn = BigInt::from_str_radix("1186b434a022c2f9d46879a782a3846e41772edf473fab6d3bf947eadf847838", 16).unwrap();
    // let y_bn = BigInt::from_str_radix("3e6c83d5c03fe71f144d474a0db2c3ae0850d5950063daa7c1b3372d28159906", 16).unwrap();
    // let pk = Secp256k1Point::from_coor(&x_bn, &y_bn);
    //
    // check_sig(&r, &s, &message_bn, &pk); // pass

    // // pk derived from raw sig sent to rinkeby using v = 0
    // let x_bn = BigInt::from_str_radix("afa18b2e5b39259d0033c5f961e9d1c9f2fb67b66742af8bc381576b3f06a24a", 16).unwrap();
    // let y_bn = BigInt::from_str_radix("d129358bf8128a34446a4ba6da999dc805d04f1c8f26d3b92fc3dd2f6ead7f27", 16).unwrap();
    // let pk = Secp256k1Point::from_coor(&x_bn, &y_bn); // fail
    //
    // check_sig(&r, &s, &message_bn, &pk);

    // // pk derived from raw sig sent to rinkeby using v = 1
    // let x_bn = BigInt::from_str_radix("c349b4dcb04e9457d2d082a4c7a714188a6456d1fcfeb5784433cab261116522", 16).unwrap();
    // let y_bn = BigInt::from_str_radix("03f8cb60ef8a327a6458aea5ef23bf8dc1631b3376cf804f66c3593a0c44817f", 16).unwrap();
    // let pk = Secp256k1Point::from_coor(&x_bn, &y_bn); // fail
    //
    // check_sig(&r, &s, &message_bn, &pk);

    // calculate public key from public shares
    let mut y_vec = Vec::<GE>::new();
    let x1_bn = BigInt::from_str_radix("15c7be9aa7150447a9693be9e92614630f6916f93d33bc35d078da4073bfd845", 16).unwrap();
    let y1_bn = BigInt::from_str_radix("8c29d5b300c211c9e95b40ef14e69d0fa7a5d8fa2965caaa0c22997605aef03f", 16).unwrap();
    let y1 = Secp256k1Point::from_coor(&x1_bn, &y1_bn);
    y_vec.push(y1);

    let x2_bn = BigInt::from_str_radix("2245f0e39ed4ed8f720697edd278c4719ed329363fce1c4993d701558928c87", 16).unwrap();
    let y2_bn = BigInt::from_str_radix("7d269abba29d2503680ce4f0af3bf2d307c140924510e63388d6e834e8017066", 16).unwrap();
    let y2 = Secp256k1Point::from_coor(&x2_bn, &y2_bn);
    y_vec.push(y2);

    let x3_bn = BigInt::from_str_radix("bc54afa1b36879d768b12c9a3dff7a0a7ba91b51a779053b6187885e8e12ec6e", 16).unwrap();
    let y3_bn = BigInt::from_str_radix("76e5468fb830216d29dc0ceb176d454f1fdef2995c6d6eaec3945539a3f3be62", 16).unwrap();
    let y3 = Secp256k1Point::from_coor(&x3_bn, &y3_bn);
    y_vec.push(y3);

    let (head, tail) = y_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0], |acc, x| acc + x);

    println!("y_sum: x: {:?}, y: {:?}", y_sum.x_coor().unwrap(), y_sum.y_coor().unwrap());
}