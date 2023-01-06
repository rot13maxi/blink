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