import { TwistedEd25519PrivateKey } from "../../src/crypto";
import { genRegistrationProof, verifyRegistrationProof } from "../../src/crypto/confidentialRegistration";
import { ed25519GenRandom } from "../../src/utils";
import { numberToBytesLE } from "@noble/curves/abstract/utils";

describe("Registration Proof (ZKPoK of Decryption Key)", () => {
  const chainId = 1;
  const senderAddress = new Uint8Array(32).fill(0xa1);
  /** Package address (`@aptos_experimental`); included in FS transcript on-chain. */
  const contractAddress = new Uint8Array(32).fill(0x55);
  const tokenAddress = new Uint8Array(32).fill(0xfa);

  function makeKey(): TwistedEd25519PrivateKey {
    const scalar = ed25519GenRandom();
    return new TwistedEd25519PrivateKey(numberToBytesLE(scalar, 32));
  }

  it("generates a valid registration proof", () => {
    const dk = makeKey();
    const proof = genRegistrationProof(dk, chainId, senderAddress, contractAddress, tokenAddress);

    expect(proof.commitment.length).toBe(32);
    expect(proof.response.length).toBe(32);
  });

  it("valid proof verifies successfully", () => {
    const dk = makeKey();
    const ek = dk.publicKey().toUint8Array();
    const proof = genRegistrationProof(dk, chainId, senderAddress, contractAddress, tokenAddress);

    const valid = verifyRegistrationProof(ek, proof, chainId, senderAddress, contractAddress, tokenAddress);
    expect(valid).toBe(true);
  });

  it("proof fails with wrong chain ID", () => {
    const dk = makeKey();
    const ek = dk.publicKey().toUint8Array();
    const proof = genRegistrationProof(dk, chainId, senderAddress, contractAddress, tokenAddress);

    const valid = verifyRegistrationProof(ek, proof, 99, senderAddress, contractAddress, tokenAddress);
    expect(valid).toBe(false);
  });

  it("proof fails with wrong sender address", () => {
    const dk = makeKey();
    const ek = dk.publicKey().toUint8Array();
    const proof = genRegistrationProof(dk, chainId, senderAddress, contractAddress, tokenAddress);

    const wrongSender = new Uint8Array(32).fill(0xbb);
    const valid = verifyRegistrationProof(ek, proof, chainId, wrongSender, contractAddress, tokenAddress);
    expect(valid).toBe(false);
  });

  it("proof fails with wrong token address", () => {
    const dk = makeKey();
    const ek = dk.publicKey().toUint8Array();
    const proof = genRegistrationProof(dk, chainId, senderAddress, contractAddress, tokenAddress);

    const wrongToken = new Uint8Array(32).fill(0xcc);
    const valid = verifyRegistrationProof(ek, proof, chainId, senderAddress, contractAddress, wrongToken);
    expect(valid).toBe(false);
  });

  it("proof fails with wrong encryption key", () => {
    const dk = makeKey();
    const proof = genRegistrationProof(dk, chainId, senderAddress, contractAddress, tokenAddress);

    const otherDk = makeKey();
    const otherEk = otherDk.publicKey().toUint8Array();
    const valid = verifyRegistrationProof(otherEk, proof, chainId, senderAddress, contractAddress, tokenAddress);
    expect(valid).toBe(false);
  });

  it("different keys produce different proofs", () => {
    const dk1 = makeKey();
    const dk2 = makeKey();
    const proof1 = genRegistrationProof(dk1, chainId, senderAddress, contractAddress, tokenAddress);
    const proof2 = genRegistrationProof(dk2, chainId, senderAddress, contractAddress, tokenAddress);

    // Commitments should differ (random nonce)
    expect(proof1.commitment).not.toEqual(proof2.commitment);
  });

  it("same key produces different proofs each time (random nonce)", () => {
    const dk = makeKey();
    const proof1 = genRegistrationProof(dk, chainId, senderAddress, contractAddress, tokenAddress);
    const proof2 = genRegistrationProof(dk, chainId, senderAddress, contractAddress, tokenAddress);

    // Commitments should differ due to random k
    expect(proof1.commitment).not.toEqual(proof2.commitment);

    // But both should verify
    const ek = dk.publicKey().toUint8Array();
    expect(verifyRegistrationProof(ek, proof1, chainId, senderAddress, contractAddress, tokenAddress)).toBe(true);
    expect(verifyRegistrationProof(ek, proof2, chainId, senderAddress, contractAddress, tokenAddress)).toBe(true);
  });

  it("proof fails with wrong contract address", () => {
    const dk = makeKey();
    const ek = dk.publicKey().toUint8Array();
    const proof = genRegistrationProof(dk, chainId, senderAddress, contractAddress, tokenAddress);
    const wrongContract = new Uint8Array(32).fill(0x66);
    expect(verifyRegistrationProof(ek, proof, chainId, senderAddress, wrongContract, tokenAddress)).toBe(false);
  });
});
