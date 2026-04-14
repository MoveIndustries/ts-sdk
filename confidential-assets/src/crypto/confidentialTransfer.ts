import { bytesToNumberLE, concatBytes, numberToBytesLE } from "@noble/curves/abstract/utils";
import { RistrettoPoint } from "@noble/curves/ed25519";
import { utf8ToBytes } from "@noble/hashes/utils";
import { PROOF_CHUNK_SIZE, SIGMA_PROOF_TRANSFER_SIZE, PROTOCOL_ID_TRANSFER } from "../consts";
import { fiatShamirChallenge } from "./fiatShamir";
import {
  AVAILABLE_BALANCE_CHUNK_COUNT,
  CHUNK_BITS,
  CHUNK_BITS_BIG_INT,
  ChunkedAmount,
  MAX_CONFIDENTIAL_TRANSFER_PLAINTEXT,
  TRANSFER_AMOUNT_CHUNK_COUNT,
} from "./chunkedAmount";
import { AnyNumber, HexInput } from "@moveindustries/ts-sdk";
import { RangeProofExecutor } from "./rangeProof";
import { TwistedEd25519PrivateKey, TwistedEd25519PublicKey, H_RISTRETTO } from ".";
import { TwistedElGamalCiphertext } from "./twistedElGamal";
import { ed25519GenListOfRandom, ed25519GenRandom, ed25519modN, ed25519InvertN } from "../utils";
import { EncryptedAmount } from "./encryptedAmount";
import { bcsSerializeMoveVectorU8 } from "../utils/moveBcs";

export type ConfidentialTransferSigmaProof = {
  alpha1List: Uint8Array[];
  alpha2: Uint8Array;
  alpha3List: Uint8Array[];
  alpha4List: Uint8Array[];
  alpha5: Uint8Array;
  alpha6List: Uint8Array[];
  X1: Uint8Array;
  X2List: Uint8Array[];
  X3List: Uint8Array[];
  X4List: Uint8Array[];
  X5: Uint8Array;
  X6List: Uint8Array[];
  X7List?: Uint8Array[];
  X8List: Uint8Array[];
};

export type ConfidentialTransferRangeProof = {
  rangeProofAmount: Uint8Array;
  rangeProofNewBalance: Uint8Array;
};

export type CreateConfidentialTransferOpArgs = {
  senderDecryptionKey: TwistedEd25519PrivateKey;
  senderAvailableBalanceCipherText: TwistedElGamalCiphertext[];
  amount: AnyNumber;
  recipientEncryptionKey: TwistedEd25519PublicKey;
  auditorEncryptionKeys?: TwistedEd25519PublicKey[];
  transferAmountRandomness?: bigint[];
  /** Chain ID for domain separation */
  chainId: number;
  /** 32-byte sender address */
  senderAddress: Uint8Array;
  /** 32-byte `confidential_asset` package address (`@aptos_experimental`) */
  contractAddress: Uint8Array;
  /** 32-byte token address */
  tokenAddress: Uint8Array;
  /**
   * Opaque bytes emitted on `Transferred` and bound into the transfer sigma Fiat–Shamir hash (BCS `vector<u8>`).
   * Must match what you submit as the last argument to `confidential_transfer` (max 256 bytes on-chain).
   */
  senderAuditorHint?: Uint8Array;
};

export class ConfidentialTransfer {
  senderDecryptionKey: TwistedEd25519PrivateKey;

  recipientEncryptionKey: TwistedEd25519PublicKey;

  auditorEncryptionKeys: TwistedEd25519PublicKey[];

  transferAmountEncryptedByAuditors: EncryptedAmount[];

  /**
   * The encrypted actual balance, which is the on-chain representation of the balance of the sender before the transfer.
   * This is can be decrypted with the sender decryption key.
   */
  senderEncryptedAvailableBalance: EncryptedAmount;

  /**
   * The encrypted amount being transferred, which is the amount to be transferred encrypted with the public key of senderDecryptionKey
   * and transferAmountRandomness.
   */
  transferAmountEncryptedBySender: EncryptedAmount;

  /**
   * The encrypted balance remaining after the transfer. It is the computed by encrypting confidentialBalanceAfterTransfer
   * with the public key of senderDecryptionKey and newBalanceRandomness.
   **/
  senderEncryptedAvailableBalanceAfterTransfer: EncryptedAmount;

  /**
   * The encrypted amount being transferred, which is the amount to be transferred encrypted with recipientEncryptionKey
   * and transferAmountRandomness.
   */
  transferAmountEncryptedByRecipient: EncryptedAmount;

  /**
   * The randomness used to encrypt the amount to be transferred.
   */
  transferAmountRandomness: bigint[];

  /**
   * The randomness used to encrypt the balance after the transfer.
   */
  newBalanceRandomness: bigint[];

  chainId: number;

  senderAddress: Uint8Array;

  contractAddress: Uint8Array;

  tokenAddress: Uint8Array;

  /** Opaque hint bytes bound into the transfer sigma Fiat–Shamir hash (same as on-chain `sender_auditor_hint`). */
  senderAuditorHint: Uint8Array;

  private constructor(args: {
    senderDecryptionKey: TwistedEd25519PrivateKey;
    recipientEncryptionKey: TwistedEd25519PublicKey;
    amount: bigint;
    auditorEncryptionKeys: TwistedEd25519PublicKey[];
    senderEncryptedAvailableBalance: EncryptedAmount;
    transferAmountEncryptedBySender: EncryptedAmount;
    transferAmountEncryptedByRecipient: EncryptedAmount;
    transferAmountEncryptedByAuditors: EncryptedAmount[];
    senderEncryptedAvailableBalanceAfterTransfer: EncryptedAmount;
    chainId: number;
    senderAddress: Uint8Array;
    contractAddress: Uint8Array;
    tokenAddress: Uint8Array;
    senderAuditorHint: Uint8Array;
  }) {
    const {
      senderDecryptionKey,
      recipientEncryptionKey,
      auditorEncryptionKeys,
      senderEncryptedAvailableBalance,
      amount,
      transferAmountEncryptedBySender,
      transferAmountEncryptedByRecipient,
      transferAmountEncryptedByAuditors,
      senderEncryptedAvailableBalanceAfterTransfer,
      senderAuditorHint,
    } = args;
    this.senderDecryptionKey = senderDecryptionKey;
    this.recipientEncryptionKey = recipientEncryptionKey;
    this.auditorEncryptionKeys = auditorEncryptionKeys;
    this.senderEncryptedAvailableBalance = senderEncryptedAvailableBalance;
    if (amount < 0n) {
      throw new Error("Amount to transfer must not be negative");
    }
    const remainingBalance = senderEncryptedAvailableBalance.getAmount() - amount;
    if (remainingBalance < 0n) {
      throw new Error(
        `Insufficient balance. Available balance: ${senderEncryptedAvailableBalance.getAmount().toString()}, Amount to transfer: ${amount.toString()}`,
      );
    }
    this.transferAmountEncryptedBySender = transferAmountEncryptedBySender;
    this.transferAmountEncryptedByRecipient = transferAmountEncryptedByRecipient;
    this.transferAmountEncryptedByAuditors = transferAmountEncryptedByAuditors;
    this.senderEncryptedAvailableBalanceAfterTransfer = senderEncryptedAvailableBalanceAfterTransfer;

    const transferAmountRandomness = transferAmountEncryptedBySender.getRandomness();
    if (!transferAmountRandomness) {
      throw new Error("Transfer amount randomness is not set");
    }
    this.transferAmountRandomness = transferAmountRandomness;

    const newBalanceRandomness = senderEncryptedAvailableBalanceAfterTransfer.getRandomness();
    if (!newBalanceRandomness) {
      throw new Error("New balance randomness is not set");
    }
    this.newBalanceRandomness = newBalanceRandomness;
    this.chainId = args.chainId;
    this.senderAddress = args.senderAddress;
    this.contractAddress = args.contractAddress;
    this.tokenAddress = args.tokenAddress;
    this.senderAuditorHint = new Uint8Array(senderAuditorHint);
  }

  static async create(args: CreateConfidentialTransferOpArgs) {
    const {
      senderAvailableBalanceCipherText,
      senderDecryptionKey,
      recipientEncryptionKey,
      auditorEncryptionKeys = [],
      transferAmountRandomness = ed25519GenListOfRandom(AVAILABLE_BALANCE_CHUNK_COUNT),
      chainId,
      senderAddress,
      contractAddress,
      tokenAddress,
      senderAuditorHint = new Uint8Array(),
    } = args;
    const amount = BigInt(args.amount);
    const newBalanceRandomness = ed25519GenListOfRandom(AVAILABLE_BALANCE_CHUNK_COUNT);

    const senderEncryptedAvailableBalance = await EncryptedAmount.fromCipherTextAndPrivateKey(
      senderAvailableBalanceCipherText,
      senderDecryptionKey,
    );
    const remainingBalance = senderEncryptedAvailableBalance.getAmount() - amount;
    const senderEncryptedAvailableBalanceAfterTransfer = EncryptedAmount.fromAmountAndPublicKey({
      amount: remainingBalance,
      publicKey: senderDecryptionKey.publicKey(),
      randomness: newBalanceRandomness,
    });

    const chunkedAmount = ChunkedAmount.createTransferAmount(amount);
    const transferAmountEncryptedBySender = new EncryptedAmount({
      chunkedAmount,
      publicKey: senderDecryptionKey.publicKey(),
      randomness: transferAmountRandomness,
    });

    const transferAmountEncryptedByRecipient = new EncryptedAmount({
      chunkedAmount,
      publicKey: recipientEncryptionKey,
      randomness: transferAmountRandomness,
    });

    const transferAmountEncryptedByAuditors = auditorEncryptionKeys.map(
      (encryptionKey) =>
        new EncryptedAmount({
          chunkedAmount,
          publicKey: encryptionKey,
          randomness: transferAmountRandomness,
        }),
    );

    return new ConfidentialTransfer({
      senderDecryptionKey,
      recipientEncryptionKey,
      auditorEncryptionKeys,
      senderEncryptedAvailableBalance,
      amount,
      transferAmountEncryptedBySender,
      transferAmountEncryptedByRecipient,
      transferAmountEncryptedByAuditors,
      senderEncryptedAvailableBalanceAfterTransfer,
      chainId,
      senderAddress,
      contractAddress,
      tokenAddress,
      senderAuditorHint,
    });
  }

  static FIAT_SHAMIR_SIGMA_DST = "MovementConfidentialAsset/Transfer";

  static serializeSigmaProof(sigmaProof: ConfidentialTransferSigmaProof): Uint8Array {
    return concatBytes(
      ...sigmaProof.alpha1List,
      sigmaProof.alpha2,
      ...sigmaProof.alpha3List,
      ...sigmaProof.alpha4List,
      sigmaProof.alpha5,
      ...sigmaProof.alpha6List,
      sigmaProof.X1,
      ...sigmaProof.X2List,
      ...sigmaProof.X3List,
      ...sigmaProof.X4List,
      sigmaProof.X5,
      ...sigmaProof.X6List,
      ...(sigmaProof.X7List ?? []),
      ...sigmaProof.X8List,
    );
  }

  static deserializeSigmaProof(sigmaProof: Uint8Array): ConfidentialTransferSigmaProof {
    if (sigmaProof.length % PROOF_CHUNK_SIZE !== 0) {
      throw new Error(`Invalid sigma proof length: the length must be a multiple of ${PROOF_CHUNK_SIZE}`);
    }

    if (sigmaProof.length < SIGMA_PROOF_TRANSFER_SIZE) {
      throw new Error(
        `Invalid sigma proof length of confidential transfer: got ${sigmaProof.length}, expected minimum ${SIGMA_PROOF_TRANSFER_SIZE}`,
      );
    }

    const totalChunks = sigmaProof.length / PROOF_CHUNK_SIZE;
    const extraXChunks = totalChunks - SIGMA_PROOF_TRANSFER_SIZE / PROOF_CHUNK_SIZE;
    if (extraXChunks % 4 !== 0) {
      throw new Error(
        `Invalid confidential transfer sigma proof: extra X chunks (${extraXChunks}) must be a multiple of 4 (per auditor row)`,
      );
    }
    const numAuditorXRows = extraXChunks / 4;

    const chunks: Uint8Array[] = [];
    for (let i = 0; i < totalChunks; i++) {
      chunks.push(sigmaProof.subarray(i * PROOF_CHUNK_SIZE, (i + 1) * PROOF_CHUNK_SIZE));
    }

    const alpha1List = chunks.slice(0, 8);
    const alpha2 = chunks[8];
    const alpha3List = chunks.slice(9, 13);
    const alpha4List = chunks.slice(13, 17);
    const alpha5 = chunks[17];
    const alpha6List = chunks.slice(18, 26);

    const x0 = 26;
    const X1 = chunks[x0];
    const X2List = chunks.slice(x0 + 1, x0 + 9);
    const X3List = chunks.slice(x0 + 9, x0 + 13);
    const X4List = chunks.slice(x0 + 13, x0 + 17);
    const X5 = chunks[x0 + 17];
    const X6List = chunks.slice(x0 + 18, x0 + 26);
    const x7Start = x0 + 26;
    const X7List = numAuditorXRows > 0 ? chunks.slice(x7Start, x7Start + numAuditorXRows * 4) : [];
    const x8Start = x7Start + numAuditorXRows * 4;
    const X8List = chunks.slice(x8Start, x8Start + 4);

    return {
      alpha1List,
      alpha2,
      alpha3List,
      alpha4List,
      alpha5,
      alpha6List,
      X1,
      X2List,
      X3List,
      X4List,
      X5,
      X6List,
      X7List,
      X8List,
    };
  }

  async genSigmaProof(): Promise<ConfidentialTransferSigmaProof> {
    if (this.transferAmountRandomness && this.transferAmountRandomness.length !== AVAILABLE_BALANCE_CHUNK_COUNT)
      throw new TypeError("Invalid length list of randomness");

    if (this.transferAmountEncryptedBySender.getAmount() > MAX_CONFIDENTIAL_TRANSFER_PLAINTEXT)
      throw new TypeError(
        `Amount must be at most ${MAX_CONFIDENTIAL_TRANSFER_PLAINTEXT} (${TRANSFER_AMOUNT_CHUNK_COUNT}×${CHUNK_BITS}-bit chunks)`,
      );

    const senderPKRistretto = RistrettoPoint.fromHex(this.senderDecryptionKey.publicKey().toUint8Array());
    const recipientPKRistretto = RistrettoPoint.fromHex(this.recipientEncryptionKey.toUint8Array());

    // Prover selects random x1, x2, x3i[], x4j[], x5, x6i[], where i in {0..AVAILABLE_BALANCE_CHUNK_COUNT-1} and j in {0..TRANSFER_AMOUNT_CHUNK_COUNT-1}
    const i = AVAILABLE_BALANCE_CHUNK_COUNT;
    const j = TRANSFER_AMOUNT_CHUNK_COUNT;

    const x1List = ed25519GenListOfRandom(i);
    const x2 = ed25519GenRandom();
    const x3List = ed25519GenListOfRandom(j);
    const x4List = ed25519GenListOfRandom(j);
    const x5 = ed25519GenRandom();
    const x6List = ed25519GenListOfRandom(i);

    // const lastHalfIndexesOfChunksCount = Array.from(
    //   { length: ChunkedAmount.CHUNKS_COUNT_HALF },
    //   // eslint-disable-next-line @typescript-eslint/no-shadow
    //   (_, i) => i + ChunkedAmount.CHUNKS_COUNT_HALF,
    // );

    // Match Move `prove_transfer`: H * scalar_sub(linear_combo(x6s, pow2_0..7), linear_combo(x3s, pow2_0..3)),
    // not H*mod(sum6) - H*mod(sum3).
    const linCombPow2 = (scalars: bigint[], len: number) =>
      scalars.slice(0, len).reduce((acc, el, idx) => acc + el * 2n ** (BigInt(idx) * CHUNK_BITS_BIG_INT), 0n);
    const hCoeff = ed25519modN(linCombPow2(x6List, i) - linCombPow2(x3List, j));

    const X1 = RistrettoPoint.BASE.multiply(
      ed25519modN(
        x1List.reduce((acc, el, idx) => {
          const coef = 2n ** (BigInt(idx) * CHUNK_BITS_BIG_INT);
          const x1i = el * coef;

          return acc + x1i;
        }, 0n),
      ),
    )
      .add(H_RISTRETTO.multiply(hCoeff))
      .add(
        this.senderEncryptedAvailableBalance
          .getCipherText()
          .reduce(
            (acc, { D }, idx) => acc.add(D.multiply(2n ** (BigInt(idx) * CHUNK_BITS_BIG_INT))),
            RistrettoPoint.ZERO,
          )
          .multiply(x2),
      )
      .subtract(
        this.senderEncryptedAvailableBalanceAfterTransfer
          .getCipherText()
          .reduce(
            (acc, { D }, idx) => acc.add(D.multiply(2n ** (BigInt(idx) * CHUNK_BITS_BIG_INT))),
            RistrettoPoint.ZERO,
          )
          .multiply(x2),
      )
      // .add(
      //   lastHalfIndexesOfChunksCount.reduce(
      //     (acc, curr) =>
      //       acc.add(
      //         H_RISTRETTO.multiply(x3List[curr]).multiply(2n ** (CHUNK_BITS_BI * BigInt(curr))),
      //       ),
      //     RistrettoPoint.ZERO,
      //   ),
      // )
      .toRawBytes();
    const X2List = x6List.map((el) => senderPKRistretto.multiply(el).toRawBytes());
    const X3List = x3List.slice(0, j).map((x3) => recipientPKRistretto.multiply(x3).toRawBytes());
    const X4List = x4List
      .slice(0, j)
      .map((x4, idx) => RistrettoPoint.BASE.multiply(x4).add(H_RISTRETTO.multiply(x3List[idx])).toRawBytes());
    const X5 = H_RISTRETTO.multiply(x5).toRawBytes();
    const X6List = x1List.map((el, idx) => {
      const x1iG = RistrettoPoint.BASE.multiply(el);
      const x6iH = H_RISTRETTO.multiply(x6List[idx]);

      return x1iG.add(x6iH).toRawBytes();
    });
    const X7List =
      this.auditorEncryptionKeys
        .map((pk) => pk.toUint8Array())
        .map((pk) => x3List.slice(0, j).map((el) => RistrettoPoint.fromHex(pk).multiply(el).toRawBytes())) ?? [];
    const X8List = x3List.map((el) => senderPKRistretto.multiply(el).toRawBytes());

    const p = fiatShamirChallenge(
      PROTOCOL_ID_TRANSFER,
      this.chainId,
      this.senderAddress,
      this.contractAddress,
      RistrettoPoint.BASE.toRawBytes(),
      H_RISTRETTO.toRawBytes(),
      this.senderDecryptionKey.publicKey().toUint8Array(),
      this.recipientEncryptionKey.toUint8Array(),
      ...this.auditorEncryptionKeys.map((pk) => pk.toUint8Array()),
      this.senderEncryptedAvailableBalance.getCipherTextBytes(),
      this.transferAmountEncryptedByRecipient.getCipherTextBytes(),
      ...this.transferAmountEncryptedByAuditors.map((el) => el.getCipherTextDPointBytes()).flat(),
      this.transferAmountEncryptedBySender.getCipherTextDPointBytes(),
      this.senderEncryptedAvailableBalanceAfterTransfer.getCipherTextBytes(),
      X1,
      ...X2List,
      ...X3List,
      ...X4List,
      X5,
      ...X6List,
      ...X7List.flat(),
      ...X8List,
      bcsSerializeMoveVectorU8(this.senderAuditorHint),
    );

    const sLE = bytesToNumberLE(this.senderDecryptionKey.toUint8Array());
    const invertSLE = ed25519InvertN(sLE);

    const alpha1List = x1List.map((x1, idx) =>
      ed25519modN(x1 - ed25519modN(p * this.senderEncryptedAvailableBalanceAfterTransfer.getAmountChunks()[idx])),
    );
    const alpha2 = ed25519modN(x2 - p * sLE);
    const alpha3List = x3List.map((el, idx) =>
      ed25519modN(BigInt(el) - p * BigInt(this.transferAmountRandomness[idx])),
    );
    const alpha4List = x4List
      .slice(0, j)
      .map((el, idx) => ed25519modN(el - p * this.transferAmountEncryptedBySender.getAmountChunks()[idx]));
    const alpha5 = ed25519modN(x5 - p * invertSLE);
    const alpha6List = x6List.map((el, idx) => ed25519modN(el - p * this.newBalanceRandomness[idx]));

    return {
      alpha1List: alpha1List.map((a) => numberToBytesLE(a, 32)),
      alpha2: numberToBytesLE(alpha2, 32),
      alpha3List: alpha3List.map((a) => numberToBytesLE(a, 32)),
      alpha4List: alpha4List.map((a) => numberToBytesLE(a, 32)),
      alpha5: numberToBytesLE(alpha5, 32),
      alpha6List: alpha6List.map((a) => numberToBytesLE(a, 32)),
      X1,
      X2List,
      X3List,
      X4List,
      X5,
      X6List,
      X7List: X7List.flat(),
      X8List,
    };
  }

  static verifySigmaProof(opts: {
    senderPrivateKey: TwistedEd25519PrivateKey;
    recipientPublicKey: TwistedEd25519PublicKey;
    encryptedActualBalance: TwistedElGamalCiphertext[];
    encryptedActualBalanceAfterTransfer: EncryptedAmount;
    encryptedTransferAmountByRecipient: EncryptedAmount;
    encryptedTransferAmountBySender: EncryptedAmount;
    sigmaProof: ConfidentialTransferSigmaProof;
    auditors?: {
      publicKeys: TwistedEd25519PublicKey[];
      auditorsCBList: TwistedElGamalCiphertext[][];
    };
    chainId: number;
    senderAddress: Uint8Array;
    contractAddress: Uint8Array;
    tokenAddress: Uint8Array;
    /** Must match the hint used when the proof was generated (BCS `vector<u8>` in Fiat–Shamir). */
    senderAuditorHint?: Uint8Array;
  }): boolean {
    const auditorPKs = opts?.auditors?.publicKeys.map((pk) => pk.toUint8Array()) ?? [];
    const proofX7List = opts.sigmaProof.X7List ?? [];

    const alpha1LEList = opts.sigmaProof.alpha1List.map((a) => bytesToNumberLE(a));
    const alpha2LE = bytesToNumberLE(opts.sigmaProof.alpha2);
    const alpha3LEList = opts.sigmaProof.alpha3List.map((a) => bytesToNumberLE(a));
    const alpha4LEList = opts.sigmaProof.alpha4List.map((a) => bytesToNumberLE(a));
    const alpha5LE = bytesToNumberLE(opts.sigmaProof.alpha5);
    const alpha6LEList = opts.sigmaProof.alpha6List.map((a) => bytesToNumberLE(a));

    const senderPublicKeyU8 = opts.senderPrivateKey.publicKey().toUint8Array();
    const recipientPublicKeyU8 = opts.recipientPublicKey.toUint8Array();
    const senderPKRistretto = RistrettoPoint.fromHex(senderPublicKeyU8);
    const recipientPKRistretto = RistrettoPoint.fromHex(recipientPublicKeyU8);

    const p = fiatShamirChallenge(
      PROTOCOL_ID_TRANSFER,
      opts.chainId,
      opts.senderAddress,
      opts.contractAddress,
      RistrettoPoint.BASE.toRawBytes(),
      H_RISTRETTO.toRawBytes(),
      senderPublicKeyU8,
      recipientPublicKeyU8,
      ...auditorPKs,
      ...opts.encryptedActualBalance.map((el) => el.serialize()).flat(),
      opts.encryptedTransferAmountByRecipient.getCipherTextBytes(),
      ...(opts.auditors?.auditorsCBList?.flat().map(({ D }) => D.toRawBytes()) || []),
      opts.encryptedTransferAmountBySender.getCipherTextDPointBytes(),
      opts.encryptedActualBalanceAfterTransfer.getCipherTextBytes(),
      opts.sigmaProof.X1,
      ...opts.sigmaProof.X2List,
      ...opts.sigmaProof.X3List,
      ...opts.sigmaProof.X4List,
      opts.sigmaProof.X5,
      ...opts.sigmaProof.X6List,
      ...proofX7List,
      ...opts.sigmaProof.X8List,
      bcsSerializeMoveVectorU8(opts.senderAuditorHint ?? new Uint8Array()),
    );

    const { oldDSum, oldCSum } = opts.encryptedActualBalance.reduce(
      (acc, { C, D }, i) => {
        const coef = 2n ** (BigInt(i) * CHUNK_BITS_BIG_INT);
        return {
          oldDSum: acc.oldDSum.add(D.multiply(coef)),
          oldCSum: acc.oldCSum.add(C.multiply(coef)),
        };
      },
      { oldDSum: RistrettoPoint.ZERO, oldCSum: RistrettoPoint.ZERO },
    );

    const newDSum = opts.encryptedActualBalanceAfterTransfer.getCipherText().reduce((acc, { D }, i) => {
      const coef = 2n ** (BigInt(i) * CHUNK_BITS_BIG_INT);
      return acc.add(D.multiply(coef));
    }, RistrettoPoint.ZERO);

    const j = TRANSFER_AMOUNT_CHUNK_COUNT;

    // const lastHalfIndexesOfChunksCount = Array.from(
    //   { length: ChunkedAmount.CHUNKS_COUNT_HALF },
    //   (_, i) => i + ChunkedAmount.CHUNKS_COUNT_HALF,
    // );

    const amountCSum = opts.encryptedTransferAmountByRecipient
      .getCipherText()
      .slice(0, j)
      .reduce((acc, { C }, i) => {
        const coef = 2n ** (BigInt(i) * CHUNK_BITS_BIG_INT);
        return acc.add(C.multiply(coef));
      }, RistrettoPoint.ZERO);

    const linCombAlphaPow2 = (scalars: bigint[], len: number) =>
      scalars.slice(0, len).reduce((acc, el, idx) => acc + el * 2n ** (BigInt(idx) * CHUNK_BITS_BIG_INT), 0n);
    const verifyHCoeff = ed25519modN(
      linCombAlphaPow2(alpha6LEList, AVAILABLE_BALANCE_CHUNK_COUNT) -
        linCombAlphaPow2(alpha3LEList, TRANSFER_AMOUNT_CHUNK_COUNT),
    );

    const X1 = RistrettoPoint.BASE.multiply(
      ed25519modN(
        alpha1LEList.reduce((acc, curr, idx) => {
          const coef = 2n ** (BigInt(idx) * CHUNK_BITS_BIG_INT);
          const a1i = curr * coef;

          return acc + a1i;
        }, 0n),
      ),
    )
      .add(H_RISTRETTO.multiply(verifyHCoeff))
      .add(oldDSum.multiply(alpha2LE))
      .subtract(newDSum.multiply(alpha2LE))
      .add(oldCSum.multiply(p))
      .subtract(amountCSum.multiply(p));
    // .add(
    //   lastHalfIndexesOfChunksCount.reduce(
    //     (acc, curr) =>
    //       acc.add(
    //         H_RISTRETTO.multiply(alpha3LEList[curr]).multiply(
    //           2n ** (CHUNK_BITS_BI * BigInt(curr)),
    //         ),
    //       ),
    //     RistrettoPoint.ZERO,
    //   ),
    // )
    const X2List = alpha6LEList.map((el, i) =>
      senderPKRistretto.multiply(el).add(opts.encryptedActualBalanceAfterTransfer.getCipherText()[i].D.multiply(p)),
    );
    const X3List = alpha3LEList
      .slice(0, j)
      .map((a3, i) =>
        recipientPKRistretto.multiply(a3).add(opts.encryptedTransferAmountByRecipient.getCipherText()[i].D.multiply(p)),
      );
    const X4List = alpha4LEList.slice(0, j).map((a4, i) => {
      const a4G = RistrettoPoint.BASE.multiply(a4);
      const a3H = H_RISTRETTO.multiply(alpha3LEList[i]);
      const pC = opts.encryptedTransferAmountByRecipient.getCipherText()[i].C.multiply(p);
      return a4G.add(a3H).add(pC);
    });
    const X5 = H_RISTRETTO.multiply(alpha5LE).add(senderPKRistretto.multiply(p));
    const X6List = alpha1LEList.map((el, i) => {
      const a1iG = RistrettoPoint.BASE.multiply(el);
      const a6iH = H_RISTRETTO.multiply(alpha6LEList[i]);
      const pC = opts.encryptedActualBalanceAfterTransfer.getCipherText()[i].C.multiply(p);
      return a1iG.add(a6iH).add(pC);
    });
    const X7List = auditorPKs.map((auPk, auPubKIdx) =>
      alpha3LEList
        .slice(0, j)
        .map((a3, idxJ) =>
          RistrettoPoint.fromHex(auPk)
            .multiply(a3)
            .add(RistrettoPoint.fromHex(opts.auditors!.auditorsCBList[auPubKIdx][idxJ].D.toRawBytes()).multiply(p)),
        ),
    );
    const X8List = alpha3LEList.map((el, i) => {
      const a3P = senderPKRistretto.multiply(el);
      const pD = opts.encryptedTransferAmountBySender.getCipherText()[i].D.multiply(p);
      return a3P.add(pD);
    });

    return (
      X1.equals(RistrettoPoint.fromHex(opts.sigmaProof.X1)) &&
      X2List.every((X2, i) => X2.equals(RistrettoPoint.fromHex(opts.sigmaProof.X2List[i]))) &&
      X3List.every((X3, i) => X3.equals(RistrettoPoint.fromHex(opts.sigmaProof.X3List[i]))) &&
      X4List.every((X4, i) => X4.equals(RistrettoPoint.fromHex(opts.sigmaProof.X4List[i]))) &&
      X5.equals(RistrettoPoint.fromHex(opts.sigmaProof.X5)) &&
      X6List.every((X6, i) => X6.equals(RistrettoPoint.fromHex(opts.sigmaProof.X6List[i]))) &&
      X7List.flat().every((X7, i) => X7.equals(RistrettoPoint.fromHex(proofX7List[i]))) &&
      X8List.every((X8, i) => X8.equals(RistrettoPoint.fromHex(opts.sigmaProof.X8List[i])))
    );
  }

  async genRangeProof(): Promise<ConfidentialTransferRangeProof> {
    const rangeProofAmount = await RangeProofExecutor.genBatchRangeZKP({
      v: this.transferAmountEncryptedBySender.getAmountChunks(),
      rs: this.transferAmountRandomness.slice(0, TRANSFER_AMOUNT_CHUNK_COUNT).map((el) => numberToBytesLE(el, 32)),
      val_base: RistrettoPoint.BASE.toRawBytes(),
      rand_base: H_RISTRETTO.toRawBytes(),
      num_bits: CHUNK_BITS,
    });

    const rangeProofNewBalance = await RangeProofExecutor.genBatchRangeZKP({
      v: this.senderEncryptedAvailableBalanceAfterTransfer.getAmountChunks(),
      rs: this.newBalanceRandomness.map((el) => numberToBytesLE(el, 32)),
      val_base: RistrettoPoint.BASE.toRawBytes(),
      rand_base: H_RISTRETTO.toRawBytes(),
      num_bits: CHUNK_BITS,
    });

    return {
      rangeProofAmount: rangeProofAmount.proof,
      rangeProofNewBalance: rangeProofNewBalance.proof,
    };
  }

  async authorizeTransfer(): Promise<
    [
      { sigmaProof: ConfidentialTransferSigmaProof; rangeProof: ConfidentialTransferRangeProof },
      EncryptedAmount,
      EncryptedAmount,
      EncryptedAmount[],
    ]
  > {
    const sigmaProof = await this.genSigmaProof();

    const rangeProof = await this.genRangeProof();

    return [
      {
        sigmaProof,
        rangeProof,
      },
      this.senderEncryptedAvailableBalanceAfterTransfer,
      this.transferAmountEncryptedByRecipient,
      this.transferAmountEncryptedByAuditors,
    ];
  }

  static async verifyRangeProof(opts: {
    encryptedAmountByRecipient: EncryptedAmount;
    encryptedActualBalanceAfterTransfer: EncryptedAmount;
    rangeProofAmount: Uint8Array;
    rangeProofNewBalance: Uint8Array;
  }) {
    const isAmountValid = await RangeProofExecutor.verifyBatchRangeZKP({
      proof: opts.rangeProofAmount,
      comm: opts.encryptedAmountByRecipient.getCipherText().map((el) => el.C.toRawBytes()),
      val_base: RistrettoPoint.BASE.toRawBytes(),
      rand_base: H_RISTRETTO.toRawBytes(),
      num_bits: CHUNK_BITS,
    });
    const isBalanceValid = await RangeProofExecutor.verifyBatchRangeZKP({
      proof: opts.rangeProofNewBalance,
      comm: opts.encryptedActualBalanceAfterTransfer.getCipherText().map((el) => el.C.toRawBytes()),
      val_base: RistrettoPoint.BASE.toRawBytes(),
      rand_base: H_RISTRETTO.toRawBytes(),
      num_bits: CHUNK_BITS,
    });
    return isAmountValid && isBalanceValid;
  }
}
