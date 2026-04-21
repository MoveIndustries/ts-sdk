pragma circom 2.0.0;

// Minimal circuit for Groth16 key material / proof pipeline tests (not a spend circuit).
template Multiplier2() {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b;
}

component main = Multiplier2();
