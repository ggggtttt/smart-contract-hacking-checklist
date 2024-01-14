# Smart Contract Hacking Humble Checklist [EVM]

## Randomness
- [ ] Does it use global variables e.g. block.timestamp, block.number, block.difficulty as a source of randomness?
- [ ] Watch out for `blockhash(uint blockNumber)` as: `blockhash(uint blockNumber) returns (bytes32)`: hash of the given block - only works for 256 most recent blocks - https://docs.soliditylang.org/en/v0.8.23/cheatsheet.html.
- [ ] The block.prevrandao - is not a source of randomness - https://eips.ethereum.org/EIPS/eip-4399.
- [x] Does it use Chainlink VRF (Verifiable Random Function)?
- [ ] Can attacker front-run Chainlink VRF's random number return? (https://medium.com/cyfrin/chainlink-oracle-defi-attacks-93b6cb6541bf)

## Arithemtic operations, overflow and underflow
- [ ] Does it use solidity version below <=0.7.x and any math library?
- [ ] Does it use solidity version above >=0.8.x and any `unchecked{}`?
- [ ] Does it cast any bigger type into smaller type e.g. uint16 into uint8? (Including solidity 0.8.x).
- [ ] Remember that subtraction may result in underflow or in transaction revert (Deny of Service).
- [ ] In case of possible underflow, maybe assertion can be bypassed `require(getBalance[msg.sender] - _value >= 0);`
- [ ] Remember that multiplication or addition may result in overflow or in transaction revert (Deny of Service).
- [ ] Remember that division by zero will revert (Deny of Service).
- [ ] Watch out for power function: 10 ** n is correct, whereas 10 ^ n is incorrect.
- [ ] Does it perform division before multiplication? (Rounding issues).
- [ ] Watch out for processing ERC20 tokens with different decimal numbers; they need normalisation. 

## Phishing attacks
- [ ] The tx.origin is always EOA.
- [ ] The msg.sender changes within calls, firstly it is EOA, then it can be contract.
- [ ] The assertion require(tx.origin == msg.sender) may have a sense in some use cases.
- [ ] The assertion require(tx.origin == owner) is rather vulnerable.

## Reentrancy 
- [ ] Basic conditions: external call + sending native tokens + state update after transaction.
- [ ] function some() payable { ... }
- [ ] address(to).call{value: amount}("");
- [ ] fallback() external payable { ... } (msg.data should not be empty)
- [ ] receive() external payable { ... } (msg.data should be empty)

![image](https://github.com/ggggtttt/sch-checklist/assets/20614295/6f518118-83c7-40e0-94e5-f1bcaf7e263e)

- [ ] Whether Checks Effects Interactions (CEI) pattern is in place?
- [ ] The onERC721Received() can cause reentrancy for ERC721, NFTs.
- [ ] The onERC1155Received(), onERC1155BatchReceived() can cause reentrancy for ERC1155
- [ ] ERC777 can cause reentrancy as it supports hooks (ERC20).
- [ ] In general, any token transfer can be vulnerable, if hook is possible.
- [x] Does it apply CEI?
- [x] Does it use ReentrancyGuard or other mutex?

## Access Control 
- [ ] Functions visiblity: pulbic, external, internal, private.
- [ ] Default function visibility for solc<0.5.0 - it is public.
- [ ] Default function visibility for solc>=0.5.0 - there is no such; code will not compile.
- [ ] Variables visibility: public, internal, private.
- [ ] Default variable visibility: internal.
- [ ] Ownable vs Ownable2Step.
- [ ] AccessControl vs AccessControlDefaultAdminRules.
- [ ] Some function are meant to be internal/private but are set to public.
- [ ] Sometimes access control modifier (e.g. onlyOwner) is missing.
- [ ] For solc<0.5.0 check whether there is any important function without explicit visibility stated.
- [ ] Double check whether `require` is indeed in use.
- [ ] Double check every `require` assertion whether it logically has a sense.
- [ ] Double check whether ownership can be stolen.

## Replay attack
- [ ] Assymetric signing - sign message with private key, and anyone can confirm it with public key.
- [ ] ECDSA - Eliptic Cruve Digital Signature Algorithm, creates keys based on seed phrase.
- [ ] Public Key == Public Address.
- [ ] ERC712 - (Typed structured data hashing and signing - domain separator, name, version, chainId, verifyingContract, salt).
- [ ] EIP191 - before EIP712.
- [ ] ERC20 Permit uses sginatures.
- [ ] ERC20 Permit uses one transaction instead of two, there is no need for approval anymore.
- [ ] Interesting issue related to Permit frontrun: https://www.trust-security.xyz/post/permission-denied
- [ ] OpenZepplin's ERC20 uses deadline, nonce and ECDSA.recover().
- [ ] Create a message, hash it and sign the hash.
- [ ] The ecrecover() - recovers Public Address of signer, based on hash and v,r,s.
- [ ] The ecrecover() - on failure, it returns address(0).
- [ ] Signature can be replayed on the same chain or other chain.
- [ ] Also watch out for malleable signatures: https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-4h98-2769-gh6h
- [ ] Signature may be frontrunned before replayed as well
- [x] To protect against replay attack on the same chain use nonces.
- [x] To protect against replay attack on the other chain use domain separator.
- [x] To protect against frontrun include msg.sender in the signature.
- [x] To mitigate replay attack add deadline
- [ ] Double check what is signed and what is not signed (but still used elsewhere).
- [ ] Double check whether it checks the signer correctly.
- [ ] Double check whether there is a need to check against address(0).
- [ ] Extra: it is worth to understand why ECDSA has s included:
- [ ] https://medium.com/draftkings-engineering/signature-malleability-7a804429b14a
- [ ] https://www.derpturkey.com/inherent-malleability-of-ecdsa-signatures/

## FlashLoans and Flashswaps
- [ ] Flashloan allows to borrow some money within single transaction, without collateral, but all must be paid along with the fees.
- [ ] Only contract can request it.
- [ ] In AAVE fee is 0,09%.
- [ ] Flashswap is done in UniSwap pair.
- [ ] Flashswap allows to swap tokenA for tokenB without having tokenA, but tokens must be returned alongwith the fees.
- [ ] Only contract can request it.
- [ ] In UniSwap fee is 0,3%.
- [ ] Governance attack.
- [ ] Price manipulation attack.
- [ ] Manipulate staking reward.
- [x] Prevention: decentralize oracle price feeds.
- [x] Prevention: split/break logic into two functions.  

## DoS
- [ ] Dependend on the owner - lost of keys.
- [ ] Dependend on the extneral call - the call reverts, e.g. reverts on Ether receive.
- [ ] Dependend on the external data - manipulate contract's balance.
- [ ] Dependend on the gas usage - unlimitted array length manipulation, gas griefing attacks.
- [x] Never trust function input.
- [x] Never trust external function return value.
- [x] Never trust external data.
- [x] Limit gas for external usage.
- [x] Avoid unbounded arrays.

## Sensitive on-chain data
- [ ] All data are visible and readable on blockchain.
- [ ] Private and internal variables are visible.
- [ ] 32 bytes slots.
- [ ] Slots start from 0.
- [ ] Cast storage [0xaddress] [slot_no] --rpc-url

## Unchecked returns
- [ ] failure !== revert
- [ ] Sometimes failure == return false.
- [ ] All low-level calls do not revert in case of failure - they return boolean.
- [ ] The transfer() - high-level call, the 2300 gas stipend is given as for external call, reverts on failure, deprecated and not recommended.
- [ ] The send() - low-level call, the 2300 gas stipend is given as for external call, returns false on failure, deprecated and not recommended.
- [ ] The call() - low-level call, forwardas all gas or custom gas, returns true/false, return value and data value should be verified, can be used to send Ether.
- [ ] The delegateCall() - low-level call,
- [ ] The staticCall() - low-level call,
- [ ] IERC20 interface also returns booleans, that should be checked (This may cause issue for non-ERC20 standard tokens).
- [ ] $ZRX, $BAT do not revert on failure, they return false
- [ ] $USDT ~~does not revert on failure and~~ does not retun false, it returns void (empty, null).
- [ ] $USDC does revert
- [x] Use SafeERC20 as a protection measure
- [ ] When considering issues with transfer() and transferFrom() value return; don't forget about approve as well! (The approve() returns boolean as well).
- [x] Allways check low-level call result and revert on failure.

## Frontrunning
- [ ] Initialization or setup attacks.
- [ ] On-chain games, loteries.
- [ ] Sandwitch attacks on DEXes.
- [ ] Defi protocols intergrated with *Swaps.
- [ ] Business logic specific.

## Sandwitch attack
- [ ] Happens for DEXes.
- [ ] Happens in the same block.
- [ ] Before and after the attacked transaction.
- [ ] Attacked transaction is in the middle.
- [ ] It is usually: Buy [Buy] and Sell.

## Oracles
- [ ] Price feed.
- [ ] Random Number Generation.
- [ ] Off-chain, on-chain, centralised, decentralised.
- [ ] Off-chain: hybrid, on-chain contract but off-chain infrastructure.
- [ ] Off-chain: Chainlink.
- [ ] On-chain: DEXes, AMMs.
- [ ] On-chain Oracles that bases on DEX (pair) can be manipulated: checking the price based on pair's balances/reserves (liquidity pool) is rather vulnerable. Flashloans/Flashswaps could be used for manipulations.
- [ ] On-chain: don't use balances for price verification (flashswap).
- [ ] On-chain: don't use reserves for price verification (flashloan).
- [ ] UniSwap TWAP: not perfect but it exists and works.
- [ ] Time Weighted Average Price (TWAP). Uniswap monitors price change over time. Can't manipulate price with flashloan/flashswap.
- [ ] Attacke vectors: stolen keys and compromised oracle.
- [ ] Attacke vectors: Use flashloan/flashswap to manipulate price by manipulating balances/reserves (liquidity pool).
- [x] Use multiple sources.
- [x] Agregate on-chain and off-chain.
- [x] Have a fallback mechanism -> other oracle, pause.

## Low level calls, proxies
- [ ] Low level functions: call(), delegateCall(), staticCall() does not revert when you call not existing address, it will return true!
- [ ] Unchecked result of call() can be vulnerability, as the call may failed.
- [ ] Passing input parameters into low level calls might be dangerous.
- [ ] Minimal Proxies - EIP 1167, factory that deploys clones.
- [ ] UUPS is prefered over Transparent Proxy at it has upgrade function in the implementation and not in proxy, so it can be removed.
- [ ] Storage colission: between proxy and implementation.
- [ ] Storage colission: between old and new implementatio.n
- [ ] Initialization issues: initalization should be doable only once.
- [ ] Frontrunning issues.
- [ ] Key leakage and centralization issues.
- [ ] Attack and modify (or destroy) the implementation.

## Yield Optimizer, Vault
- [ ] ERC4626.
- [ ] FIRST DEPOSITOR CAN BREAK MINTING OF SHARES:
- [ ] https://github.com/OpenZeppelin/openzeppelin-contracts/issues/3706
- [ ] https://github.com/code-423n4/2022-09-y2k-finance-findings/issues/449
- [ ] Very first deposit can be frontrun to exploit shares calculations.
- [ ] Condition: vault must work with token balances, not properties.
- [ ] Attacker must deposit tiny value, e.g. 1, then he/she receives tiny value of shares.
- [ ] Attacker must send some tokens to vault directly.
- [ ] Above action makes total supply increased (denominator in some calculation).
- [ ] Victim gets tiny value of shares upon deposit.
- [ ] Proportionally, the attacker can now withdraw huge amount of assets.
- [x] Make initial deposit in constructor.
- [x] Require minimum amount for deposit.

## Gas Griefing
- [ ] The 63/64 rule: external calls are delegated with the 63/64 of remaining gas.
- [ ] Call stack depth limit - 1024.
- [ ] Call stack depth attack - obsolete vulnerability, where attacker were performing 1023 external calls to enfore next to revert.
- [x] Specifying gas limit for external call is considered good practice.
- [ ] In gas griefing attack the attacker attempts to use all 63/64 gas forwarded within the external call; so when the execution is finished, the initial contract will likely revert with remaining 1/64 gas.
- [ ] Gas can be consumed as well when external function returns data back to the initial contract; bytes memory data may have huge payload that will consume remaining gas; e.g. huge string.
- [x] Consider try catch or assembly to handle low level call; in such way the data is not AUTOMATICALLY coppied to memory.
- [ ] However, try catch may attempt to decode revert data!
- [ ] As a payload: huge string can be generated with inline assembly: just pretend that string is huge be setting length with mstore.

## Dex
- [ ] DEX - Decentralised Exchanges.
- [ ] Examples: UniSwap, SushiSwap (yield farming), PancakeSwap (Binance).
- [ ] Permissionless, accessible.
- [ ] Liquidity Provissioning; liquidity pools.
- [ ] Swaps, AAM.
- [ ] Trading fees.
- [ ] AMM - Automated Market Maker
- [ ] k = x * y (pool_amount_0 * pool_amount_1 = total_amount_ratio), k is constant during swap.
- [ ] UniSwap: FactoryContract - creates pairs.
- [ ] UniSwap: Router - user facing contract.
- [ ] UniSwap: PairContract - holds the liquidity.

## Money Markets
- [ ] Lending Protocols.
- [ ] Lend and earn interest.
- [ ] Borrow and pay interest.
- [ ] Protocol fees.
- [ ] Collateral is required.
- [ ] It must use price feeds (oracles).
- [ ] The max_borrow << collateral.
- [ ] Liqudiation: when max_borrow ~= collateral. (Liquidation threshold).
- [ ] LTV - Loan To Value.
- [ ] APY - Annual Percantage Yield - > yield/interest after a year.
- [ ] APY - does not include compounded interest.
- [ ] Reserve/underlying asset - real asset, deposited, used as colateral.
- [ ] AAVE LIQUIDITY PROTOCOL - Aave is an Open Source Protocol to create Non-Custodial Liquidity Markets (...).
- [ ] AAVE - Pools.
- [ ] AAVE - Tokens (ATokens).
- [ ] Compound is an algorithmic, autonomous interest rate protocol built for developers, (...).
- [ ] Compound - Comptroller, simillar to AAVE's Pool.
- [ ] Compound - CTokens.
