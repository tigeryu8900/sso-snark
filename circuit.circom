pragma circom 2.0.0;

include "./node_modules/circomlib/circuits/poseidon.circom";

template Hasher(nbits) {
    signal input password;
    signal input nonce;
    signal output hash;

    component poseidon = Poseidon(2);

    poseidon.inputs[0] <== password;
    poseidon.inputs[1] <== nonce;
    hash <== poseidon.out;
}

component main {public [nonce]} = Hasher(32);
