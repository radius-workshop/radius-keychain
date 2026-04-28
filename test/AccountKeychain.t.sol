// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {AccountKeychain} from "../src/AccountKeychain.sol";
import {MockUSDC} from "../src/MockUSDC.sol";

contract AccountKeychainTest is Test {
    AccountKeychain public keychain;
    MockUSDC public usdc;

    address owner = makeAddr("owner");
    address agent;
    uint256 agentKey;
    address recipient = makeAddr("recipient");
    bytes32 keyId = bytes32(uint256(1));

    function setUp() public {
        keychain = new AccountKeychain();
        usdc = new MockUSDC();
        (agent, agentKey) = makeAddrAndKey("agent");

        usdc.mint(owner, 10_000e6);
        vm.prank(owner);
        usdc.approve(address(keychain), type(uint256).max);
    }

    function _signTokenTransfer(address to, uint128 amount, uint256 nonce)
        internal
        view
        returns (bytes memory)
    {
        bytes32 inner = keccak256(
            abi.encode(address(keychain), owner, keyId, address(usdc), to, amount, nonce, block.chainid)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_authorizeKey() public {
        vm.prank(owner);
        keychain.authorizeKey(keyId, agent, uint64(block.timestamp + 1 days));
        AccountKeychain.AccessKey memory k = keychain.getKey(owner, keyId);
        assertEq(k.signer, agent);
        assertFalse(k.revoked);
    }

    function test_revokeKey() public {
        vm.prank(owner);
        keychain.authorizeKey(keyId, agent, 0);
        vm.prank(owner);
        keychain.revokeKey(keyId);
        AccountKeychain.AccessKey memory k = keychain.getKey(owner, keyId);
        assertTrue(k.revoked);
    }

    function test_executeTokenTransfer() public {
        vm.prank(owner);
        keychain.authorizeKey(keyId, agent, 0);

        bytes memory sig = _signTokenTransfer(recipient, 100e6, 0);
        keychain.executeTokenTransfer(owner, keyId, address(usdc), recipient, 100e6, sig);
        assertEq(usdc.balanceOf(recipient), 100e6);
    }

    function test_spendingLimit_enforced() public {
        vm.prank(owner);
        keychain.authorizeKey(keyId, agent, 0);
        vm.prank(owner);
        keychain.setSpendingLimit(keyId, address(usdc), 50e6, 1 days);

        bytes memory sig = _signTokenTransfer(recipient, 50e6, 0);
        keychain.executeTokenTransfer(owner, keyId, address(usdc), recipient, 50e6, sig);

        bytes memory sig2 = _signTokenTransfer(recipient, 1e6, 1);
        vm.expectRevert(AccountKeychain.SpendingLimitExceeded.selector);
        keychain.executeTokenTransfer(owner, keyId, address(usdc), recipient, 1e6, sig2);
    }

    function test_spendingLimit_resets_after_period() public {
        vm.prank(owner);
        keychain.authorizeKey(keyId, agent, 0);
        vm.prank(owner);
        keychain.setSpendingLimit(keyId, address(usdc), 50e6, 1 days);

        bytes memory sig = _signTokenTransfer(recipient, 50e6, 0);
        keychain.executeTokenTransfer(owner, keyId, address(usdc), recipient, 50e6, sig);

        vm.warp(block.timestamp + 1 days + 1);

        bytes memory sig2 = _signTokenTransfer(recipient, 50e6, 1);
        keychain.executeTokenTransfer(owner, keyId, address(usdc), recipient, 50e6, sig2);
        assertEq(usdc.balanceOf(recipient), 100e6);
    }

    function test_expired_key_reverts() public {
        vm.prank(owner);
        keychain.authorizeKey(keyId, agent, uint64(block.timestamp + 1 hours));

        vm.warp(block.timestamp + 2 hours);

        bytes memory sig = _signTokenTransfer(recipient, 10e6, 0);
        vm.expectRevert(AccountKeychain.KeyExpired.selector);
        keychain.executeTokenTransfer(owner, keyId, address(usdc), recipient, 10e6, sig);
    }

    function test_revoked_key_reverts() public {
        vm.prank(owner);
        keychain.authorizeKey(keyId, agent, 0);
        vm.prank(owner);
        keychain.revokeKey(keyId);

        bytes memory sig = _signTokenTransfer(recipient, 10e6, 0);
        vm.expectRevert(AccountKeychain.KeyIsRevoked.selector);
        keychain.executeTokenTransfer(owner, keyId, address(usdc), recipient, 10e6, sig);
    }

    function test_remainingBudget() public {
        vm.prank(owner);
        keychain.authorizeKey(keyId, agent, 0);
        vm.prank(owner);
        keychain.setSpendingLimit(keyId, address(usdc), 100e6, 1 days);

        assertEq(keychain.remainingBudget(owner, keyId, address(usdc)), 100e6);

        bytes memory sig = _signTokenTransfer(recipient, 30e6, 0);
        keychain.executeTokenTransfer(owner, keyId, address(usdc), recipient, 30e6, sig);

        assertEq(keychain.remainingBudget(owner, keyId, address(usdc)), 70e6);
    }

    function _signExecuteByKey(address target, uint256 value, bytes memory data, uint256 nonce)
        internal
        view
        returns (bytes memory)
    {
        bytes32 inner = keccak256(
            abi.encode(address(keychain), owner, keyId, target, value, data, nonce, block.chainid)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_selfCall_blocked() public {
        vm.prank(owner);
        keychain.authorizeKey(keyId, agent, 0);
        vm.prank(owner);
        keychain.addCallScope(keyId, address(keychain), bytes4(keccak256("authorizeKey(bytes32,address,uint64)")));

        bytes memory data = abi.encodeWithSelector(
            keychain.authorizeKey.selector, bytes32(uint256(99)), agent, uint64(0)
        );
        bytes memory sig = _signExecuteByKey(address(keychain), 0, data, 0);
        vm.expectRevert(AccountKeychain.SelfCallBlocked.selector);
        keychain.executeByKey(owner, keyId, address(keychain), 0, data, sig);
    }

    function test_emptyScopes_reverts() public {
        vm.prank(owner);
        keychain.authorizeKey(keyId, agent, 0);

        bytes memory data = abi.encodeWithSelector(MockUSDC.mint.selector, recipient, 100e6);
        bytes memory sig = _signExecuteByKey(address(usdc), 0, data, 0);
        vm.expectRevert(AccountKeychain.NoCallScopes.selector);
        keychain.executeByKey(owner, keyId, address(usdc), 0, data, sig);
    }

    function test_executeByKey_with_scope() public {
        vm.prank(owner);
        keychain.authorizeKey(keyId, agent, 0);
        vm.prank(owner);
        keychain.addCallScope(keyId, address(usdc), MockUSDC.mint.selector);

        bytes memory data = abi.encodeWithSelector(MockUSDC.mint.selector, recipient, 100e6);
        bytes memory sig = _signExecuteByKey(address(usdc), 0, data, 0);
        keychain.executeByKey(owner, keyId, address(usdc), 0, data, sig);
        assertEq(usdc.balanceOf(recipient), 100e6);
    }

    function test_wrongSigner_reverts() public {
        vm.prank(owner);
        keychain.authorizeKey(keyId, agent, 0);

        (address rogue, uint256 rogueKey) = makeAddrAndKey("rogue");
        bytes32 inner = keccak256(
            abi.encode(address(keychain), owner, keyId, address(usdc), recipient, uint128(10e6), uint256(0), block.chainid)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(rogueKey, digest);

        vm.expectRevert(AccountKeychain.InvalidSignature.selector);
        keychain.executeTokenTransfer(owner, keyId, address(usdc), recipient, 10e6, abi.encodePacked(r, s, v));
    }
}
