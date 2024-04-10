// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {BN254} from "./libraries/BN254.sol";

struct SignatureParam {
    BN254.G1Point[] signerPubkeys;
    BN254.G2Point apkG2; // is the aggregate G2 pubkey of all signers
    BN254.G1Point sigma; // is the aggregate G1 signature of all signers
}

/**
 * @title BLS SignatureChecker
 * @author Confucian
 * @notice demonstrates how to verify BLS aggregate signatures
 */
contract SignatureChecker {
    using BN254 for BN254.G1Point;

    // gas cost of multiplying 2 pairings
    uint256 internal constant PAIRING_EQUALITY_CHECK_GAS = 120_000;
    // The hash of the zero pubkey aka BN254.G1Point(0,0)
    bytes32 internal constant ZERO_PK_HASH = hex"ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5";

    /**
     * @dev checkSignature verifies a BLS aggregate signature
     * @param msgHash message hash
     * @param param SignatureParam
     */
    function checkSignature(bytes32 msgHash, SignatureParam memory param) public view returns (bool, bool) {
        BN254.G1Point memory apk = BN254.G1Point(0, 0);

        ///@dev add to calculate apk
        for (uint256 i = 0; i < param.signerPubkeys.length; i++) {
            apk = apk.plus(param.signerPubkeys[i]);
        }

        BN254.G1Point memory apkTemp = BN254.G1Point(0, 0);
        BN254.G1Point memory apkGen = BN254.generatorG1();
        for (uint256 j = 0; j < 256 - param.signerPubkeys.length; j++) {
            apkTemp = apkTemp.plus(apkGen);
        }

        (bool pairingSuccessful, bool signatureIsValid) =
            trySignatureAndApkVerification(msgHash, apk, param.apkG2, param.sigma);

        return (pairingSuccessful, signatureIsValid);
    }

    /**
     * trySignatureAndApkVerification verifies a BLS aggregate signature and the veracity of a calculated G1 Public key
     * @param msgHash is the hash being signed
     * @param apk is the claimed G1 public key
     * @param apkG2 is provided G2 public key
     * @param sigma is the G1 point signature
     * @return pairingSuccessful is true if the pairing precompile call was successful
     * @return siganatureIsValid is true if the signature is valid
     */
    function trySignatureAndApkVerification(
        bytes32 msgHash,
        BN254.G1Point memory apk,
        BN254.G2Point memory apkG2,
        BN254.G1Point memory sigma
    ) internal view returns (bool pairingSuccessful, bool siganatureIsValid) {
        // gamma = keccak256(abi.encodePacked(msgHash, apk, apkG2, sigma))
        uint256 gamma = uint256(
            keccak256(
                abi.encodePacked(
                    msgHash, apk.X, apk.Y, apkG2.X[0], apkG2.X[1], apkG2.Y[0], apkG2.Y[1], sigma.X, sigma.Y
                )
            )
        ) % BN254.FR_MODULUS;
        // verify the signature
        (pairingSuccessful, siganatureIsValid) = BN254.safePairing(
            sigma.plus(apk.scalar_mul(gamma)),
            BN254.negGeneratorG2(),
            BN254.hashToG1(msgHash).plus(BN254.generatorG1().scalar_mul(gamma)),
            apkG2,
            PAIRING_EQUALITY_CHECK_GAS
        );
    }
}
