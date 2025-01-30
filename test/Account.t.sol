// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import {MockERC1271Wallet} from "@solady/test/utils/mocks/MockERC1271Wallet.sol";
import {Ownable, SignatureCheckerLib} from "@solady/src/accounts/ERC4337.sol";
import {ERC4337, MockERC4337} from "@solady/test/utils/mocks/MockERC4337.sol";
import {MockEntryPoint} from "@solady/test/utils/mocks/MockEntryPoint.sol";
import {MockERC1155} from "@solady/test/utils/mocks/MockERC1155.sol";
import {MockERC721} from "@solady/test/utils/mocks/MockERC721.sol";
import {LibString} from "@solady/src/utils/LibString.sol";
import {LibClone} from "@solady/src/utils/LibClone.sol";
import {LibZip} from "@solady/src/utils/LibZip.sol";

import "@solady/test/utils/SoladyTest.sol";

import {Account} from "../src/Account.sol";
import {console} from "forge-std/Test.sol";

contract AccountTest is SoladyTest {

    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);


    address internal erc4337;
    Account internal account;

    bytes32 internal constant _DOMAIN_SEP_B =
    0xa1a044077d7677adbbfa892ded5390979b33993e0e2a457e3f974bbcda53821b;

    address internal constant _ENTRY_POINT=0x0000000071727De22E5E9d8BAf0edAc6f37da032; //default 

    function setUp() public {

        vm.etch(_ENTRY_POINT, hex"00");

        erc4337=address(new Account());
        account= Account(payable(LibClone.deployERC1967(erc4337)));  //erc4337 is the implementation nand a proxy is being created using the ERC1967 proxy



    }


    function testDisableInitializerForImplementation() public {

        Account mock= new Account ();
        console.log(mock.owner());
        vm.expectRevert(Ownable.AlreadyInitialized.selector);
        mock.initialize(address(this));

    }

    function testInitializer() public {

        vm.expectEmit(true, true, true , true);
        emit OwnershipTransferred(address(0), address(this));
        account.initialize(address(this));

        assertEq(account.owner(), address(this));
        vm.expectRevert(Ownable.AlreadyInitialized.selector);
        account.initialize(address(this));


        address newOwner= _randomNonZeroAddress();
        vm.expectEmit(true,true,true,true);
        emit OwnershipTransferred(address(this), newOwner);
        account.transferOwnership(newOwner);
        assertEq(account.owner(),newOwner);


        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferred(newOwner, address(this));
        vm.prank(newOwner);
        account.transferOwnership(address(this));

        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferred(address(this), address(0));
        account.renounceOwnership();
        assertEq(account.owner(), address(0));

        vm.expectRevert(Ownable.AlreadyInitialized.selector);
        account.initialize(address(this));
        assertEq(account.owner(), address(0)); //address(0) is the new owner , so no one can reinitialize the onwer as it is already being set.

        vm.prank(address(0));           //this test passes but in real adress(0) cant sign any transactions so dw we are safe
        account.transferOwnership(address(this));
        assertEq(account.owner(),address(this));


        //make a new proxy

        erc4337 =address(new Account());
        account =Account(payable(LibClone.deployERC1967(erc4337)));

        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferred(address(0), address(0));
        account.initialize(address(0));
        assertEq(account.owner(), address(0));


        vm.expectRevert(Ownable.AlreadyInitialized.selector);
        account.initialize(address(this));
        assertEq(account.owner(), address(0));


    }


    function testExecute() public {

        vm.deal(address(account),1 ether);
        account.initialize(address(this));

        address target =address(new Target());
        bytes memory data= _randomBytes();

        account.execute(target, 123, abi.encodeWithSignature("setData(bytes)", data));
        assertEq(Target(target).datahash(), keccak256(data));
        assertEq(target.balance, 123);

        vm.prank(_randomNonZeroAddress());
        vm.expectRevert(Ownable.Unauthorized.selector);
        account.execute(target, 123, abi.encodeWithSignature("setData(bytes)", data));

        vm.expectRevert(abi.encodeWithSignature("TargetError(bytes)", data));
        account.execute(target, 123, abi.encodeWithSignature("revertWithTargetError(bytes)", data));

    }



    function testExecuteBatch() public {

        vm.deal(address(account), 1 ether);
        account.initialize(address(this));


        ERC4337.Call[] memory calls= new ERC4337.Call[](2);  //Call structure for executeBatch txns

        calls[0].target=address(new Target());
        calls[1].target=address(new Target());
        calls[0].value=538;
        calls[1].value=767;
        bytes memory randBytes1=_randomBytes();
        bytes memory randBytes2=_randomBytes();
        calls[0].data = abi.encodeWithSignature("setData(bytes)", randBytes1);
        calls[1].data = abi.encodeWithSignature("setData(bytes)", randBytes2);

        account.executeBatch(calls);
        assertEq(Target(calls[0].target).datahash(), keccak256(randBytes1));
        assertEq(Target(calls[1].target).datahash(), keccak256(randBytes2));
        assertEq(calls[0].target.balance, 538);
        assertEq(calls[1].target.balance, 767);


        calls[1].data = abi.encodeWithSignature("revertWithTargetError(bytes)", randBytes1);
        vm.expectRevert(abi.encodeWithSignature("TargetError(bytes)", randBytes1));
        account.executeBatch(calls);


        
    }

    function testDelegateExecute() public {

        vm.deal(address(account), 1 ether);
        account.initialize(address(this));

        address delegate=address(new Target());

        bytes memory data;
        bytes memory randomByte=_randomBytes();
        data =abi.encodeWithSignature("setData(bytes)", randomByte);
        data=account.delegateExecute(delegate,data);

        assertEq(abi.decode(data,(bytes)), randomByte);
        data = account.delegateExecute(delegate, abi.encodeWithSignature("datahash()"));
        assertEq(abi.decode(data, (bytes32)), keccak256(randomByte));
        data = account.delegateExecute(delegate, abi.encodeWithSignature("data()"));
        assertEq(abi.decode(data, (bytes)), randomByte);


        bytes memory TargetData;
        bytes memory zeroBytes="" ;
        TargetData=Target(delegate).data();
        assertEq(TargetData,zeroBytes);     // Storage of Target remains unchanged

    }


    function testDelegateExecuteRevertsIfOwnerSlotValueChanged() public {

        vm.deal(address(account), 1 ether);
        account.initialize(address(this));

        address delegate = address(new Target());

        bytes memory data;

        data=abi.encodeWithSignature("changeOwnerSlotValue(bool)",false);
        account.delegateExecute(delegate,data);

        vm.expectRevert();
        data = abi.encodeWithSignature("changeOwnerSlotValue(bool)", true);
        account.delegateExecute(delegate, data);


    }


    function testDepositFunctions() public {

        vm.deal(address(account), 1 ether);
        account.initialize(address(this));
        vm.etch(account.entryPoint(),address(new MockEntryPoint()).code);
        assertEq(account.getDeposit(), 0);
        account.addDeposit{value: 1 ether}();
        assertEq(account.getDeposit(),1 ether);

        address to =_randomNonZeroAddress();

        assertEq(to.balance,0);
        account.withdrawDepositTo(to, 0.5 ether);

        assertEq(to.balance, 0.5 ether);
        assertEq(account.getDeposit(),0.5 ether);

        //check if anyone other than owner can deposit?

        vm.prank(_randomNonZeroAddress());
        vm.expectRevert(Ownable.Unauthorized.selector);
        account.withdrawDepositTo(to,0.5 ether);

    }



    struct _TestTemps {
        bytes32 userOpHash;
        bytes32 contents;
        address signer;
        uint256 privateKey;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 missingAccountFunds;
    }


    function testValidUserOp() public {

        ERC4337.PackedUserOperation memory userOp;
        userOp.sender=address(account);
        userOp.nonce=4337;

        _TestTemps memory t;

        t.userOpHash=keccak256("123");
        (t.signer, t.privateKey)=_randomSigner();

        (t.v, t.r, t.s) = vm.sign(t.privateKey, _hash712(userOp, 0, 0));//sign the digest with private key

        t.missingAccountFunds=0.5 ether;

        vm.deal(address(account), 1 ether);
        assertEq(address(account).balance, 1 ether);


        account.initialize(t.signer);

        vm.etch(account.entryPoint(), address(new MockEntryPoint()).code);
        MockEntryPoint ep=MockEntryPoint(payable(account.entryPoint()));

        userOp.signature= abi.encodePacked(bytes6(0), bytes6(0), t.r, t.s, t.v); //first two args are valid time frames

        assertEq(
            ep.validateUserOp(address(account), userOp, t.userOpHash, t.missingAccountFunds), 0      //calls the validateUserOp from account contract
        ); // success returns 0
        
        
        assertEq(address(ep).balance, t.missingAccountFunds);

        userOp.signature=abi.encodePacked(bytes6(0),bytes6(0),t.r, (bytes32(uint256(t.s)^1)), /* bitwise xor */t.v );

        assertEq(
            ep.validateUserOp(address(account), userOp, t.userOpHash, t.missingAccountFunds), 1     
        ); // failure returns 1


        assertEq(address(ep).balance, 2*t.missingAccountFunds);  // as it prefunds 

        //No entry point reverts
        vm.expectRevert(Ownable.Unauthorized.selector);
        account.validateUserOp(userOp, t.userOpHash, t.missingAccountFunds);



    }


    // function testisValidSignature () public {

    //     vm.txGasPrice(10);

    //     _TestTemps memory t;
    //     t.contents=keccak256("123");
    //     (t.signer, t.privateKey)=_randomSigner();
    //     (t.v, t.r, t.s)=vm.sign(t.privateKey,_toERC1271Hash(t.contents));

    //     account.initialize(t.signer);

    //     bytes memory contentsType ="Contents(bytes32 stuff)";
    //     bytes memory signature=abi.encodePacked(
    //         t.r, t.s, t.v
    //     )



    // }





































    // HASH HELPERS

    struct _AccountDomainStruct {
        bytes1 fields;
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
        bytes32 salt;
        uint256[] extensions;
    }

    function _accountDomainStructFields() internal view returns (bytes memory) {
        _AccountDomainStruct memory t;
        (t.fields, t.name, t.version, t.chainId, t.verifyingContract, t.salt, t.extensions) =
            account.eip712Domain();

        return abi.encode(
            t.fields,
            keccak256(bytes(t.name)),
            keccak256(bytes(t.version)),
            t.chainId,
            t.verifyingContract,
            t.salt,
            keccak256(abi.encodePacked(t.extensions))
        );
    }

    function _toERC1271Hash(bytes32 contents) internal view returns (bytes32) {
        bytes32 parentStructHash = keccak256(
            abi.encodePacked(
                abi.encode(
                    keccak256(
                        "TypedDataSign(Contents contents,bytes1 fields,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt,uint256[] extensions)Contents(bytes32 stuff)"
                    ),
                    contents
                ),
                _accountDomainStructFields()
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", _DOMAIN_SEP_B, parentStructHash));
    }

    function _toContentsHash(bytes32 contents) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", _DOMAIN_SEP_B, contents));
    }

    function _toERC1271HashPersonalSign(bytes32 childHash) internal view returns (bytes32) {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("NANI"),
                keccak256("1.2.3"),
                block.chainid,
                address(account)
            )
        );
        bytes32 parentStructHash =
            keccak256(abi.encode(keccak256("PersonalSign(bytes prefixed)"), childHash));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, parentStructHash));
    }

    bytes32 internal constant _DOMAIN_TYPEHASH =
        0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    bytes32 internal constant _VALIDATE_TYPEHASH =
        0xa9a214c6f6d90f71d094504e32920cfd4d8d53e5d7cf626f9a26c88af60081c7;

    function _hash712(
        ERC4337.PackedUserOperation memory userOp,
        uint48 validUntil,
        uint48 validAfter
    ) internal view returns (bytes32 digest) {
        address _account = address(account);
        bytes32 nameHash = keccak256(bytes("arunabha003"));
        bytes32 versionHash = keccak256(bytes("1.0.0"));
        assembly ("memory-safe") {
            let m := mload(0x40) // Load the free memory pointer.
            mstore(m, _DOMAIN_TYPEHASH)
            mstore(add(m, 0x20), nameHash)
            mstore(add(m, 0x40), versionHash)
            mstore(add(m, 0x60), chainid())
            mstore(add(m, 0x80), _account)
            digest := keccak256(m, 0xa0)
        }
        bytes32 structHash = _structHash(userOp, validUntil, validAfter);
        assembly ("memory-safe") {
            // Compute the digest.
            mstore(0x00, 0x1901000000000000) // Store "\x19\x01".
            mstore(0x1a, digest) // Store the domain separator.
            mstore(0x3a, structHash) // Store the struct hash.
            digest := keccak256(0x18, 0x42)
            // Restore the part of the free memory slot that was overwritten.
            mstore(0x3a, 0)
        }
    }

    function _structHash(
        ERC4337.PackedUserOperation memory userOp,
        uint48 validUntil,
        uint48 validAfter
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                _VALIDATE_TYPEHASH,
                userOp.sender,
                userOp.nonce,
                keccak256(userOp.initCode),
                keccak256(userOp.callData),
                userOp.accountGasLimits,
                userOp.preVerificationGas,
                userOp.gasFees,
                keccak256(userOp.paymasterAndData),
                validUntil,
                validAfter
            )
        );
    }




}





contract Target {
    error TargetError(bytes data);

    bytes32 public datahash;

    bytes public data;

    function setData(bytes memory data_) public payable returns (bytes memory) {
        data = data_;
        datahash = keccak256(data_);
        return data_;
    }

    function revertWithTargetError(bytes memory data_) public payable {
        revert TargetError(data_);
    }

    function changeOwnerSlotValue(bool change) public payable {
        /// @solidity memory-safe-assembly
        assembly {
            if change { sstore(not(0x8b78c6d8), 0x112233) }  //0x8b78c6d8 is the hashed value derived from keccak256("eip1967.proxy.admin"),
        }
    }
}