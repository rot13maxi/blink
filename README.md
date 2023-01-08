## Protocol
Alice and Bob are going to swap coins.
1. Alice begins in the Init state.
2. Alice publishes a `Proposal` that contains how much she wants to swap. Alice is now in the `Proposed` state
2. Bob responds with an `Offer` that contains 2 pubkeys for the escrows, his timelock, and a hash for both hashlocks. Bob is now in the `Offered` state.
3. Alice decides if she likes Bob's timelock, and if she does, she responds to Bob with her 2 pubkeys for the escrows and her timelock. 
4. At this point Alice and Bob can both compute all the scripts for the escrows. Alice and Bob now in the `Bootstrapped` state.
5. Bob sends Alice the address that he is going to escrow coins into. Bob is in the `PendingLock` state 
6. Alice checks Bob's address and if it matches what she computed, Alice sends over the address that she computed. Alice is in the `PendingLock` state.
7. Bob checks Alice's address. If it matches what he computed, he deposits coins into his escrow address. Bob is now in the `Deposited` state.
8. Alice sees Bob's deposit. She waits for it to be confirmed and then desposits coins in her escrow. Alice is now in the `Deposited` state
9. Bob sees Alice's despoit. He waits for it to be confirmed. Once it is, he sends the hashlock preimage to Alice. Bob is now in the `PreimageRevealed` state.
10. At this point, either participant can safely get the other escrow coins. Alice is also in the `PreimageRevealed` state.
11. Once Alice gets the preimage, she sends her private key for her escrow to Bob. Alice is in the `SecKeyRevealed` state
12. Once Bob gets the private key, he sends the private key for his escrow to Alice. Bob is in the `SecKeyRevealed` state
13. Alice and Bob can now each spend the other escrow by the "happy path" and the swap is complete. They simply need to spend before the refund timelock expires. They are both in the `Closable` state until they spend, and then they will be in the `Closed` state.

If at any point after they've reached the `Deposited` state, the timelock on the refund-path of their escrow reaches maturation, they enter the `RefundSpend` state and try to get their money back.
Once a participant reaches the `Deposited` state, they monitor the chain for the other participant spending their escrow using the hashlock path. If they see it, the enter the `HashlockSpend` state and spend the other escrow using the preimage.
Before getting to `Deposited`, if `n` seconds elapse without a state transition, the participant moves to the `TimedOut` state and abandons the contract.

## TODO
- have a marker trait for maker/taker so that state transition methods can be better-typed?
- Have things return `Result` so we can get rid of some of the panics
- logging
- coordinate over nostr
- move wallet to BDK
- Have some checking around current state and state transitions in contracts
- wrap up state persistence into a top-level container type ("wallet"?)
- handle multiple UTXOs associated with a contract
- put an index in the taptree so we can have different scriptpubkeys associated with the same contract for multi-tx swaps
- change contract escrow to `map<Role, Escrow>`