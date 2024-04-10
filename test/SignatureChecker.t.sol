// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {SignatureChecker, SignatureParam} from "./../src/SignatureChecker.sol";
import {BN254} from "./../src/libraries/BN254.sol";

contract SignatureCheckerTest is Test {
    using BN254 for BN254.G1Point;

    SignatureChecker signatureChecker;

    bytes32 msgHash = keccak256(abi.encodePacked("hello world"));
    uint256 aggSignerPrivKey = 69;
    BN254.G2Point aggSignerApkG2;
    BN254.G1Point sigma;

    function setUp() public {
        signatureChecker = new SignatureChecker();

        // aggSignerPrivKey*g2
        aggSignerApkG2.X[1] = 19101821850089705274637533855249918363070101489527618151493230256975900223847;
        aggSignerApkG2.X[0] = 5334410886741819556325359147377682006012228123419628681352847439302316235957;
        aggSignerApkG2.Y[1] = 354176189041917478648604979334478067325821134838555150300539079146482658331;
        aggSignerApkG2.Y[0] = 4185483097059047421902184823581361466320657066600218863748375739772335928910;

        sigma = BN254.hashToG1(msgHash).scalar_mul(aggSignerPrivKey);
    }

    function test_checkSignature() public view {
        uint256 pseudoRandomNumber = 111;
        uint256 numSigners = 2;

        uint256[] memory signerPrivateKeys = new uint256[](numSigners);

        uint256 sum = 0;
        for (uint256 i = 0; i < numSigners - 1; i++) {
            signerPrivateKeys[i] =
                uint256(keccak256(abi.encodePacked("signerPrivateKey", pseudoRandomNumber, i))) % BN254.FR_MODULUS;
            sum = addmod(sum, signerPrivateKeys[i], BN254.FR_MODULUS);
        }

        // signer private keys need to add to aggSignerPrivKey
        signerPrivateKeys[numSigners - 1] =
            addmod(aggSignerPrivKey, BN254.FR_MODULUS - (sum % BN254.FR_MODULUS), BN254.FR_MODULUS);

        BN254.G1Point[] memory signerPubkeys = new BN254.G1Point[](numSigners);
        for (uint256 i = 0; i < numSigners; i++) {
            signerPubkeys[i] = BN254.generatorG1().scalar_mul(signerPrivateKeys[i]);
        }

        SignatureParam memory param;
        param.signerPubkeys = signerPubkeys;
        param.apkG2 = aggSignerApkG2;
        param.sigma = sigma;

        (bool pairingSuccessful, bool signatureIsValid) = signatureChecker.checkSignature(msgHash, param);

        assertTrue(pairingSuccessful);
        assertTrue(signatureIsValid);
    }
}
