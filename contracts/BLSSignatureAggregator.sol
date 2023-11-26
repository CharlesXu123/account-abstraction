//SPDX-License-Identifier: Unlicense
pragma solidity >=0.8.4 <0.9.0;
pragma abicoder v2;

import {BLSOpen} from "./lib/BLSOpen.sol";
import "./BLSHelper.sol";

import "hardhat/console.sol";

/**
 * A BLS-based signature aggregator, to validate aggregated signature of multiple UserOps if BLSAccount
 */
contract BLSSignatureAggregator {
    bytes32 public constant BLS_DOMAIN = keccak256("eip4337.bls.domain");

    //copied from BLS.sol
    uint256 public constant N =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    uint256 constant FIELD_MASK =
        0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    uint256 constant SIGN_MASK =
        0x8000000000000000000000000000000000000000000000000000000000000000;
    uint256 constant ODD_NUM =
        0x8000000000000000000000000000000000000000000000000000000000000000;

    // Negated genarator of G2
    uint256 constant nG2x1 =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant nG2x0 =
        10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant nG2y1 =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;
    uint256 constant nG2y0 =
        13392588948715843804641432497768002650278120570034223513918757245338268106653;

    /**
     * return the trailing 4 words of input data
     */
    function getTrailingPublicKey(
        bytes memory data
    ) public pure returns (uint256[4] memory publicKey) {
        uint len = data.length;
        require(len > 32 * 4, "data too short for sig");

        /* solhint-disable-next-line no-inline-assembly */
        assembly {
            // actual buffer starts at data+32, so last 128 bytes start at data+32+len-128 = data+len-96
            let ofs := sub(add(data, len), 96)
            mstore(publicKey, mload(ofs))
            mstore(add(publicKey, 32), mload(add(ofs, 32)))
            mstore(add(publicKey, 64), mload(add(ofs, 64)))
            mstore(add(publicKey, 96), mload(add(ofs, 96)))
        }
    }

    function _getPublicKeyHash(
        uint256[4] memory publicKey
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(publicKey));
    }

    function pubkeyToUncompresed(
        uint256[2] memory compressed,
        uint256[2] memory y
    ) internal pure returns (uint256[4] memory uncompressed) {
        uint256 desicion = compressed[0] & SIGN_MASK;
        require(
            desicion == ODD_NUM || y[0] & 1 != 1,
            "BLS: bad y coordinate for uncompressing key"
        );
        uncompressed[0] = compressed[0] & FIELD_MASK;
        uncompressed[1] = compressed[1];
        uncompressed[2] = y[0];
        uncompressed[3] = y[1];
    }

    function signatureToUncompresed(
        uint256 compressed,
        uint256 y
    ) internal pure returns (uint256[2] memory uncompressed) {
        uint256 desicion = compressed & SIGN_MASK;
        require(
            desicion == ODD_NUM || y & 1 != 1,
            "BLS: bad y coordinate for uncompressing key"
        );
        return [compressed & FIELD_MASK, y];
    }

    function validateUserOpSignature1(
        uint256[2] calldata signature,
        uint256[4] calldata pubkey,
        uint256[2] calldata message
    ) external view returns (bool) {
        return BLSOpen.verifySingle(signature, pubkey, message);
    }

    function validateUserOpSignature2(
        uint256[2] calldata signature,
        uint256[4] calldata pubkey,
        uint256[2] calldata message
    ) external view returns (bool) {
        uint256[12] memory input = [
            signature[0],
            signature[1],
            nG2x1,
            nG2x0,
            nG2y1,
            nG2y0,
            message[0],
            message[1],
            pubkey[1],
            pubkey[0],
            pubkey[3],
            pubkey[2]
        ];
        uint256[1] memory out;
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 8, input, 384, out, 32)
            switch success
            case 0 {
                invalid()
            }
        }
        require(success, "");
        return out[0] != 0;
    }
}
