//SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MultiSigWallet is ReentrancyGuard {

    // IMPORTS

    using ECDSA for bytes32;

    // EVENTS

    event Deposit(address from, uint amount);
    event Withdraw(address to, uint amount);
    
    // STRUCT

    struct WithdrawalInfo {
        uint amount;
        address to;
    }

    // GLOBAL VAR

    string constant private MSG_PREFIX = "\x19Ethereum Signed Message:\n32";
    mapping(address => bool) private owners;
    uint256 private _ownersCount;
    uint256 public threshold;
    uint256 public nonce;

    // MODIFIERS

    modifier isOwner() {
        require(owners[msg.sender], "Not owner");
        _;
    }

    // CONSTRUCTOR

    constructor(address[] memory _signers, uint256 _threshold) {
        require(_signers.length > 0, "Owners required");
        require(_threshold > 0 && _threshold <= _signers.length, "Invalid threshold");
        for (uint8 i = 0; i < _signers.length; i++) {
            require(_signers[i] != address(0), "Invalid owner");
            require(owners[_signers[i]] == false, "Owner not unique");
            owners[_signers[i]] = true;
        }
        _ownersCount = _signers.length;
        threshold = _threshold;
    }

    // FUNCTIONS

    function _processWithdrawalInfo(WithdrawalInfo calldata _txn, uint256 _nonce, address _contractAddress) private pure returns(bytes32 _digest) {
        bytes memory encoded = abi.encode(_txn);
        _digest = keccak256(abi.encodePacked(encoded, _nonce, _contractAddress));
        _digest = keccak256(abi.encodePacked(MSG_PREFIX, _digest));
        return _digest;
    }

    function _verifyMultiSignature(WithdrawalInfo calldata _txn, uint256 _nonce, bytes[] calldata _multiSignature) private {
        require(_nonce > nonce, "Nonce already used");
        uint256 count = _multiSignature.length;
        require(count <= _ownersCount, "Invalid number of signatures");
        require(count >= threshold, "Not enough signatures");
        bytes32 _digest = _processWithdrawalInfo(_txn, _nonce, address(this));

        address initSignerAddress;
        for (uint256 i = 0; i < count; i++) {
            bytes memory signature = _multiSignature[i];
            address signerAddress = ECDSA.recover(_digest, signature);
            require(signerAddress > initSignerAddress, "Invalid signature order or duplicate signature");
            require(owners[signerAddress], "Invalid signer");
            initSignerAddress = signerAddress;
        }
        nonce = _nonce;
    }

    function _transferETH(WithdrawalInfo calldata _txn) private {
        (bool success, ) = payable(_txn.to).call{value: _txn.amount}("");
        require(success, "Transfer failed");
    }

    function withdrawETH(WithdrawalInfo calldata _txn, uint256 _nonce, bytes[] calldata _multiSignature) external nonReentrant isOwner {
        require(_txn.amount > 0, "Invalid amount");
        require(address(this).balance >= _txn.amount, "Insufficient balance");
        _verifyMultiSignature(_txn, _nonce, _multiSignature);
        _transferETH(_txn);
        emit Withdraw(_txn.to, _txn.amount);
    }

    receive() external payable {
        emit Deposit(msg.sender, msg.value);
    }

    fallback() external payable {}

}