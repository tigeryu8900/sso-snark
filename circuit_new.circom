pragma circom 2.0.0;

include "./node_modules/circomlib/circuits/bitify.circom";
include "./node_modules/circomlib/circuits/sha256/sha256.circom";

template Multiplier(n) {
    signal input password;
    signal input nonce;
    signal output hash;

    component sha256 = Sha256(254);
    component num2bits = Num2Bits(254);
    component bits2num = Bits2Num(256);

    num2bits.in <== password * nonce;
    sha256.in <== num2bits.out;
    bits2num.in <== sha256.out;
    hash <== bits2num.out;
}

component main {public [nonce]} = Multiplier(1000);
