// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract AccountKeychain {
    using SafeERC20 for IERC20;

    struct AccessKey {
        address signer;
        uint64 expiresAt;
        bool revoked;
    }

    struct SpendingLimit {
        uint128 limit;
        uint128 spent;
        uint64 periodStart;
        uint64 periodDuration;
    }

    struct CallScope {
        address target;
        bytes4 selector;
    }

    mapping(address => mapping(bytes32 => AccessKey)) private _keys;
    mapping(address => mapping(bytes32 => mapping(address => SpendingLimit))) private _spendingLimits;
    mapping(address => mapping(bytes32 => CallScope[])) private _callScopes;
    mapping(address => uint256) public nonces;

    event KeyAuthorized(address indexed owner, bytes32 indexed keyId, address signer, uint64 expiresAt);
    event KeyRevoked(address indexed owner, bytes32 indexed keyId);
    event SpendingLimitSet(
        address indexed owner, bytes32 indexed keyId, address indexed token, uint128 limit, uint64 periodDuration
    );
    event CallScopeAdded(address indexed owner, bytes32 indexed keyId, address target, bytes4 selector);
    event ExecutedByKey(address indexed owner, bytes32 indexed keyId, address target, uint256 value, bytes data);

    error KeyNotFound();
    error KeyExpired();
    error KeyIsRevoked();
    error InvalidSignature();
    error SpendingLimitExceeded();
    error CallNotInScope();
    error NotOwner();
    error ZeroAddress();

    function authorizeKey(bytes32 keyId, address signer, uint64 expiresAt) external {
        if (signer == address(0)) revert ZeroAddress();
        _keys[msg.sender][keyId] =
            AccessKey({signer: signer, expiresAt: expiresAt, revoked: false});
        emit KeyAuthorized(msg.sender, keyId, signer, expiresAt);
    }

    function revokeKey(bytes32 keyId) external {
        AccessKey storage key = _keys[msg.sender][keyId];
        if (key.signer == address(0)) revert KeyNotFound();
        key.revoked = true;
        emit KeyRevoked(msg.sender, keyId);
    }

    function setSpendingLimit(
        bytes32 keyId,
        address token,
        uint128 limit,
        uint64 periodDuration
    ) external {
        if (_keys[msg.sender][keyId].signer == address(0)) revert KeyNotFound();
        _spendingLimits[msg.sender][keyId][token] = SpendingLimit({
            limit: limit,
            spent: 0,
            periodStart: uint64(block.timestamp),
            periodDuration: periodDuration
        });
        emit SpendingLimitSet(msg.sender, keyId, token, limit, periodDuration);
    }

    function addCallScope(bytes32 keyId, address target, bytes4 selector) external {
        if (_keys[msg.sender][keyId].signer == address(0)) revert KeyNotFound();
        _callScopes[msg.sender][keyId].push(CallScope({target: target, selector: selector}));
        emit CallScopeAdded(msg.sender, keyId, target, selector);
    }

    function executeByKey(
        address owner,
        bytes32 keyId,
        address target,
        uint256 value,
        bytes calldata data,
        bytes calldata signature
    ) external {
        AccessKey storage key = _keys[owner][keyId];
        if (key.signer == address(0)) revert KeyNotFound();
        if (key.revoked) revert KeyIsRevoked();
        if (key.expiresAt != 0 && block.timestamp > key.expiresAt) revert KeyExpired();

        uint256 nonce = nonces[owner]++;
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode(address(this), owner, keyId, target, value, data, nonce, block.chainid))
            )
        );
        address signer = ECDSA.recover(digest, signature);
        if (signer != key.signer) revert InvalidSignature();

        _checkCallScope(owner, keyId, target, data);

        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }

        emit ExecutedByKey(owner, keyId, target, value, data);
    }

    function executeTokenTransfer(
        address owner,
        bytes32 keyId,
        address token,
        address to,
        uint128 amount,
        bytes calldata signature
    ) external {
        AccessKey storage key = _keys[owner][keyId];
        if (key.signer == address(0)) revert KeyNotFound();
        if (key.revoked) revert KeyIsRevoked();
        if (key.expiresAt != 0 && block.timestamp > key.expiresAt) revert KeyExpired();

        uint256 nonce = nonces[owner]++;
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode(address(this), owner, keyId, token, to, amount, nonce, block.chainid))
            )
        );
        address signer = ECDSA.recover(digest, signature);
        if (signer != key.signer) revert InvalidSignature();

        _checkAndDebitSpending(owner, keyId, token, amount);

        IERC20(token).safeTransferFrom(owner, to, amount);

        emit ExecutedByKey(owner, keyId, token, 0, abi.encodeWithSelector(IERC20.transfer.selector, to, amount));
    }

    function getKey(address owner, bytes32 keyId) external view returns (AccessKey memory) {
        return _keys[owner][keyId];
    }

    function getSpendingLimit(address owner, bytes32 keyId, address token)
        external
        view
        returns (SpendingLimit memory)
    {
        return _spendingLimits[owner][keyId][token];
    }

    function getCallScopes(address owner, bytes32 keyId)
        external
        view
        returns (CallScope[] memory)
    {
        return _callScopes[owner][keyId];
    }

    function remainingBudget(address owner, bytes32 keyId, address token)
        external
        view
        returns (uint128)
    {
        SpendingLimit storage sl = _spendingLimits[owner][keyId][token];
        if (sl.limit == 0) return type(uint128).max;

        if (sl.periodDuration > 0 && block.timestamp >= sl.periodStart + sl.periodDuration) {
            return sl.limit;
        }
        return sl.limit > sl.spent ? sl.limit - sl.spent : 0;
    }

    function _checkCallScope(address owner, bytes32 keyId, address target, bytes calldata data)
        internal
        view
    {
        CallScope[] storage scopes = _callScopes[owner][keyId];
        if (scopes.length == 0) return;

        bytes4 selector = bytes4(data[:4]);
        for (uint256 i = 0; i < scopes.length; i++) {
            if (scopes[i].target == target && scopes[i].selector == selector) return;
        }
        revert CallNotInScope();
    }

    function _checkAndDebitSpending(address owner, bytes32 keyId, address token, uint128 amount)
        internal
    {
        SpendingLimit storage sl = _spendingLimits[owner][keyId][token];
        if (sl.limit == 0) return;

        if (sl.periodDuration > 0 && block.timestamp >= sl.periodStart + sl.periodDuration) {
            sl.spent = 0;
            sl.periodStart = uint64(block.timestamp);
        }

        if (sl.spent + amount > sl.limit) revert SpendingLimitExceeded();
        sl.spent += amount;
    }
}
