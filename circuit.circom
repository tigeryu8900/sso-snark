pragma circom 2.0.0;

template Multiplier(n) {
    signal input password;
    signal input nonce;
    signal output hash;

    signal int[n];

    int[0] <== password * password + nonce;
    for (var i = 1; i < n; i++) {
        int[i] <== int[i - 1] * int[i - 1] + nonce;
    }

    hash <== int[n - 1];
}

component main {public [nonce]} = Multiplier(1000);
