## Reentrancy
Reentrancy can only happen when your smart contract calls another smart contract via function call or sending ether.

If you do not call another contract or send ether in the middle of an execution, you cannot hand over execution control, and reentrancy cannot happen.

```javascript
function proxyVote(uint256 voteChoice) external {
    voteContract.vote(voteChoice); // hands control to voteContract
    alreadyVoted = true;
}
```
The tricky part is that you might not always know when you are calling another contract. For example, this code is actually re-entrant if this is used inside of an ERC1155 contract.
```javascript
function purchaseERC1155NFT() external {
    _mint(msg.sender, TOKEN_ID, 1, "");
    erc20Token.transferFrom(msg.sender, address(this));
}
```
Why is this innocuous looking mint unsafe? Let’s look at the code in the OpenZeppelin ERC1155 [here](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC1155/ERC1155.sol#L266).
```javascript
function _mint(
    address to,
    uint256 id,
    uint256 amount,
    bytes memory data
) internal virtual {
    require(to != address(0), "ERC1155: mint to the zero address");

    address operator = _msgSender();
    uint256[] memory ids = _asSingletonArray(id);
    uint256[] memory amounts = _asSingletonArray(amount);

    _beforeTokenTransfer(operator, address(0), to, ids, amounts, data);

    _balances[id][to] += amount;
    emit TransferSingle(operator, address(0), to, id, amount);

    _afterTokenTransfer(operator, address(0), to, ids, amounts, data);

    _doSafeTransferAcceptanceCheck(operator, address(0), to, id, amount, data);
}
```
Solidity code ERC1155

`_mint` calls `_doSafeTransferAcceptanceCheck`.
```javascript
function _doSafeTransferAcceptanceCheck(
    address operator,
    address from,
    address to,
    uint256 id,
    uint256 amount,
    bytes memory data
) private {
    if (to.isContract()) {
        try IERC1155Receiver(to).onERC1155Received(operator, from, id, amount, data) returns (bytes4 response) {
            if (response != IERC1155Receiver.onERC1155Received.selector) {
                revert("ERC1155: ERC1155Receiver rejected tokens");
            }
        } catch Error(string memory reason) {
            revert(reason);
        } catch {
            revert("ERC1155: transfer to non-ERC1155Receiver implementer");
        }
    }
}
```
Solidity code IERC1155Receiver

And there we can see that _mint will ultimately try to call a function onERC1155Received on the receiving function. Now we have handed control over to another contract.

The tool slither will automatically detect external function calls, so you should use it.

Hopefully, this doesn’t make matters more confusing, but a very similar looking code
```javascript
function purchaseERC1155NFT() external {
    _mint(msg.sender, AMOUNT);
    erc20Token.transferFrom(msg.sender, address(this));
}
```
is not re-entrant if it is derived from ERC20. That’s because under the hood, the transferFrom function in Solidity doesn’t make a function call to an external function, as you can see in its [implementation](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/ERC20.sol).
```javascript
function _transfer(
    address from,
    address to,
    uint256 amount
) internal virtual {
    require(from != address(0), "ERC20: transfer from the zero address");
    require(to != address(0), "ERC20: transfer to the zero address");

    _beforeTokenTransfer(from, to, amount);

    uint256 fromBalance = _balances[from];
    require(fromBalance >= amount, "ERC20: transfer amount exceeds balance");
    unchecked {
        _balances[from] = fromBalance - amount;
        // Overflow not possible: the sum of all balances is capped by totalSupply, and the sum is preserved by
        // decrementing then incrementing.
        _balances[to] += amount;
    }

    emit Transfer(from, to, amount);

    _afterTokenTransfer(from, to, amount);
}
```
ERC20 transfer implementation.
## ERC721
- `safeTransferFrom`
- `_safeMint`
Confusingly enough, the word “safe” means it is checking if the receiving address is a smart contract, then attempting to call the “onERC721Received” function. The `transferFrom` and `_mint` functions don’t do this, so you don’t have to worry about reentrancy.

This doesn’t mean you shouldn’t use `safeTransferFrom` or `_safeMint` methods, it means you should use the check-effects pattern or reentrancy guards to prevent reentrancy if you use it.

Here is a simple example of a mint function where the attacker can mint all the NFTs for themselves:
```javascript
contract FooToken is ERC721 {

    function mint() external payable {
        require(msg.value == 0.1 ether);
        require(!alreadyMinted[msg.sender]);

        totalSupply++;
        _safeMint(msg.sender, totalSupply);
        alreadyMinted[msg.sender] = true;
    }
}
```
## ERC1155
- `safeTransferFrom`
- `_mint`
- `safeBatchTransferFrom`
- `_mintBatch`
Even more confusing, `_mint` in ERC1155 does not behave like `_mint` in ERC721. It behaves like `_safeMint` in ERC721.

Nothing is “safe” in ERC1155. Every method calls the receiving contract. There is nothing wrong with this design choice, it just means you must follow the check-effects pattern or using reentrancy guards — as you should be doing anyway.

Here is vulnerable code for ERC1155:
```javascript
contract FooToken is ERC1155 {

    function mint(uint256 tokenId) external payable {
        require(msg.value == 0.1 ether);
        require(!alreadyMinted[msg.sender]);

        totalSupplyForTokenId[tokenId]++;
        _mint(msg.sender, totalSupplyForTokenId[tokenId], 1, "");
        alreadyMinted[msg.sender] = true;
    }
}
```
## ERC 223, 677, 777, and 1363
We can’t cover every proposed variation of ERC20 here. The fact that ERC20 transfer and transferFrom does not result in reentrancy is great, but this also creates UX issues where a smart contract can’t know it has received an ERC20 token. The above list are some proposed variations of ERC20 that try to inform the receiving smart contract they received tokens.

This should also be a warning when interacting with untrusted ERC20 tokens. They might actually be one of these standards under the hood and be capable of triggering reentrancy.

Here is the line where ERC777 calls the contract after transferring the tokens: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/release-v4.8/contracts/token/ERC777/ERC777.sol#L499:
```javascript
function _callTokensReceived(
    address operator,
    address from,
    address to,
    uint256 amount,
    bytes memory userData,
    bytes memory operatorData,
    bool requireReceptionAck
) private {
    address implementer = _ERC1820_REGISTRY.getInterfaceImplementer(to, _TOKENS_RECIPIENT_INTERFACE_HASH);
    if (implementer != address(0)) {
        IERC777Recipient(implementer).tokensReceived(operator, from, to, amount, userData, operatorData);
    } else if (requireReceptionAck) {
        require(to.isContract(), "ERC777: token recipient contract has no implementer for ERC777TokensRecipient");
    }
}
```
Solidity ERC777 reentrancy line

ERC [1363](https://eips.ethereum.org/EIPS/eip-1363) has a better UX for this. The regular transfer function behaves like a normal ERC20, so we don’t get any sneaky reentrancy issues. However, if we want to alert the contract it received tokens, we use the `transferAndCall` method.

ERC777 reentrancy has happened in the real world and can be quite catastrophic. [Here](https://blog.openzeppelin.com/exploiting-uniswap-from-reentrancy-to-actual-profit) is an example.

When designing an application that interacts with arbitrary ERC20 tokens, don’t assume `transfer` and `transferFrom` are non-reentrant.

## Sending Ether
When you send ether via `address.call(””)`, you hand over control to the other contract.

Consider the following classic example:
```javascript
contract FaultyBank {

    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        msg.sender.call{value: balances[msg.sender]}("");
        balances[msg.sender] = 0;
    }
}

```
It can be attacked in this manner:
```javascript
contract RobTheBank {

    IFaultyBank private bank;

    constructor(IFaultyBank _bank) {
        bank = _bank;
    }

    function attack() payable {
        bank.deposit{value: 1 ether}()
        bank.withdraw();
    }

    fallback() external payable {
        if (address(bank).balance >= 1 ether) {
            bank.withdraw(); // reenterancy attack here
        }
    }
}
```
Because `balances[msg.sender]` is set to zero after sending the balance, then the attacker can keep withdrawing 1 ether (stealing from other users), until the balance is below 1 ether.

## How transfer and send prevent reentrancy, and why you shouldn’t use them
As an aside, the methods `transfer()` and `send()` are not re-entrant although they can trigger the fallback and receive functions. This is because they limit the gas forwarded to 2300 gas. This is not enough for the malicious contract to re-enter the victim contract.

However, it is generally considered bad practice to use these methods. Let’s say you have a smart contract that tries to pay off a loan in another smart contract. If you pay off the loan with transfer or send, the lending contract won’t have enough gas to register the loan was paid off.

The DAO hack of 2016 was very nearly fatal to the Ethereum ecosystem, so the designers introduced these functions to prevent it from happening.

Transfer and send only forward 2300 gas when they are used. Ethereum doesn’t allow variable storage when there is less than 2300 gas available ([source](https://github.com/wolflo/evm-opcodes/blob/main/gas.md#a7-sstore)), so this means the attacking contract cannot cause a permanent state change.

The problem with transfer and send is that many contracts may deliberately want to react to receiving ether. For example, suppose you have a decentralized lender, and you want to pay back the lender by sending Ether. The lender contract sees the ether is coming from the borrower, and marks their loan as paid. However, it can’t do that if you starve it of gas.

It may seem odd that Solidity has features that you shouldn’t use, but this is part of our evolving understanding of blockchain best practices. It seemed like a good idea at the time to prevent reentrancy by limiting gas, but it turns out we cannot predict what future gas costs will be. Hardcoding gas is considered bad practice, since the gas value of opcodes can has changed.

## Cross-function reentrancy. Reentrancy does not have to enter the same function
When the victim contract makes a function call to the external contract at the wrong time, the attacking contract does not necessarily have to re-enter the same function the called it. In fact, if two functions are re-entrant, the attacker can “trampoline” (also called mutual recursion) between the functions. Some engineers refer to this as cross-function reentrancy. Here is an example of a contract which is vulnerable to this.
```javascript
contract CrossFunctionReentrancyVulnerable {

    // don't allow people to swap more than once every 24 hours
    mapping(address => uint256) public lastSwap;

    function swapAForB() {
        require(block.timestamp - lastSwap[msg.sender] >= 1 days);
        governanceTokenERC20.mint(msg.sender, AMOUNT);
        tokenAerc777.transferFrom(msg.sender, address(this));
        tokenBerc777.transferFrom(address(this), msg.sender);
        lastSwap[msg.sender] = block.timestamp;
    }

    function swapBForA() {
        require(block.timestamp - lastSwap[msg.sender] >= 1 days);
        governanceTokenERC20.mint(msg.sender, AMOUNT);
        tokenBerc777.transferFrom(msg.sender, address(this));
        tokenAerc777.transferFrom(address(this), msg.sender);
        lastSwap[msg.sender] = block.timestamp;
    }
}
```
In the code above, users can swap token A for B (and vice versa) and be rewarded with governance tokens. However the contract (tries) to limit them to swapping every 24 hours so that the governance tokens aren’t minted out too fast.

ERC777 tokens can be reentrant as noted earlier, but doing a simple reentrancy on one function won’t work because the attacker will run out of tokenA or tokenB.

However, if the attacker repeatedly swaps A for B, then they can mint out all the governance tokens for themselves.

In this case, we have made the governance token an ERC20 token so the attacker cannot reenter into the same function. However, when `transferFrom(address(this)`, `msg.sender`) is executed, the attacker gains control before the `lastSwap` mapping is updated.

## Read only Reentrancy, also known as cross contract reentrancy
Read only reentrancy entered the popular developer minds in 2022 when a [talk](https://www.youtube.com/watch?v=8D5ZJyU-dX0) at ETH Devcon explained a vulnerability in Curve finance.

Read only reentrancy is just a rebrand of an already known vulnerability, cross contract reentrancy.

If contract Foo depends on the state of another contract Bar, and Bar does not produce the correct state values mid-transaction, then Foo can be tricked.

In the Curve finance case, it wasn’t Curve that was exploited. It was contracts that depended on it. It works roughly like this:

- The attacker deposits ether and other ERC20 tokens into curve. Curve mints liquidity tokens to the attacker.
- The attacker withdraws liquidity by burning the liquidity tokens.
- Curve sends back ether before sending back the ERC20 tokens.
- When curve sends back Ether, the attacker regains control and conducts a trade on another contract
- The contract that depends on curve asks curve for the price ratio between the liquidity tokens, ether, and the other ERC20 tokens. Because the liquidity tokens have been burned, and the Ethereum has been returned to the attacker, but the ERC20 tokens are still in Curve, the calculation of prices is incorrect at this exact state in time.
- The transaction completes, and Curve sends back the ERC20 tokens, and the calculated price is now correct.
Read only reentrancy is very similar to a flash loan attack, and usually needs a flashloan to be effective.

There are two ways to defend against read only reentrancy or cross contract reentrancy. 
One is to make the reentrancy lock public or make the view functions non-reentrant also. 
The view function that reports the prices is in an incorrect state at the moment the user withdraws part of the liquidity. 
So the exchange can block people from using the view function while liquidity is being withdrawn. 
If the reentrancy lock is public, then an application that relies on the view function can check if liquidity withdrawal is in progress by checking the reentrancy lock. 
If the ether has been sent out, but not the ERC20 tokens haven’t been withdrawn yet, then the reentrancy lock will be on because the withdraw liquidity function hasn’t completed yet.

Note that this vulnerability requires sending out a sequence of assets that can trigger other functions. In the Curve case outlined above, they sent out Ether before sending ERC20 tokens. However, a similar thing could happen if ERC777 tokens were sent out.

### More Resources
- An up to date list of reentrancy attacks in the wild:
https://github.com/pcaversaccio/reentrancy-attacks
- Pre 2022 documentation on cross-contract reentrancy (read-only reentrancy)
https://inspexco.medium.com/cross-contract-reentrancy-attack-402d27a02a15
- Practice exercises:
https://capturetheether.com/challenges/miscellaneous/token-bank/
- Ethernaut:
https://ethernaut.openzeppelin.com/level/10
(note that this reentrancy attack doesn’t work on Solidity 0.8.0 or higher because underflowing the balance will result in the transaction reverting)

