// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title CaptureRegistry
 * @notice Immutable on-chain registry for CaptureChain Merkle roots.
 *         Deploy to Polygon for ~$0.001 per anchor transaction.
 */
contract CaptureRegistry {

    struct CaptureRecord {
        bytes32 merkleRoot;
        uint256 capturedAt;
        string  captureType;     // "snapshot" | "video_clip"
        address registeredBy;
    }

    mapping(bytes32 => CaptureRecord) public records;
    bytes32[] public recordIndex;

    event CaptureAnchored(
        bytes32 indexed merkleRoot,
        uint256         capturedAt,
        string          captureType,
        address indexed registeredBy
    );

    function anchorCapture(bytes32 merkleRoot, string calldata captureType) external {
        require(records[merkleRoot].capturedAt == 0, "CaptureRegistry: already anchored");

        records[merkleRoot] = CaptureRecord({
            merkleRoot:   merkleRoot,
            capturedAt:   block.timestamp,
            captureType:  captureType,
            registeredBy: msg.sender
        });

        recordIndex.push(merkleRoot);
        emit CaptureAnchored(merkleRoot, block.timestamp, captureType, msg.sender);
    }

    function verify(bytes32 merkleRoot) external view returns (bool exists, uint256 timestamp) {
        CaptureRecord memory r = records[merkleRoot];
        return (r.capturedAt != 0, r.capturedAt);
    }

    function totalAnchored() external view returns (uint256) {
        return recordIndex.length;
    }
}
