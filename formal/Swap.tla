This is a formal specification for the Swap protocol used in Blink. 

There are two participants in a swap. The participant that initiates the protocol 
is called the `proposer`. The second participant is called the `partner`.

-------------------------------- MODULE Swap --------------------------------
\* internal state enum for each participant
VARIABLES proposer_state, partner_state

participant_states == << proposer_state, partner_state >>

\* content of the most recent DM between parties
VARIABLES dm

\* status of onchain escrow transaction for each participant
VARIABLES proposer_escrow, partner_escrow

\* whether or not the escrow timelocks have matured
VARIABLES proposer_timelock_mature, partner_timelock_mature

\* collections of vars for easier `UNCHANGED` assertions
escrows == << proposer_escrow, partner_escrow >>
timelocks == << proposer_timelock_mature, partner_timelock_mature >>

vars == << proposer_state, partner_state, dm, escrows, timelocks >>

swap_states == {"init", "proposed", "offered", "bootstrapped", "pendinglock", 
                "deposited", "preimagerevealed", "seckeyrevealed", "closable", "closed",
                "closedtimelock", "cancelled"}

TypeInvariant == /\ proposer_state \in swap_states
                 /\ partner_state \in swap_states


Init == /\ proposer_state = "init"
        /\ partner_state = "init"
        /\ dm = ""
        /\ proposer_escrow = ""
        /\ partner_escrow = ""
        /\ proposer_timelock_mature = FALSE
        /\ partner_timelock_mature = FALSE

(*
 * Convenience Definitions
 *)
TimelocksOk == /\ proposer_timelock_mature = FALSE
               /\ partner_timelock_mature = FALSE

ProposerRefund == proposer_escrow = "confirmed_refund"
PartnerRefund == partner_escrow = "confirmed_refund"

\* note that each participant spends the OTHER escrow in the happy cases
ProposerPaid == partner_escrow = "confirmed_spend"
PartnerPaid == proposer_escrow = "confirmed_spend"

TerminalStates == {"closedsuccess", "closedhashlock", "closedtimelock"}
      

(*
 * Happy Path 
 *)

ProposeSwap == /\ proposer_state  = "init"
               /\ proposer_state' = "proposed"
               /\ UNCHANGED << partner_state, dm, escrows, timelocks >>

OfferSwap == /\ proposer_state = "proposed"
             /\ partner_state  = "init"
             /\ partner_state' = "offered"
             /\ dm'            = "partner_setup"
             /\ UNCHANGED  << proposer_state, escrows, timelocks >>

RespondToOffer == /\ proposer_state = "proposed"
                  /\ dm             = "partner_setup"
                  /\ partner_state  = "offered"
                  /\ \/ /\ proposer_state' = "bootstrapped"
                        /\ dm' = "proposer_setup"
                     \/ /\ proposer_state' = "cancelled"
                        /\ dm' = "cancel_swap"
                  /\ UNCHANGED << partner_state, escrows, timelocks >>

PartnerBootstrap == /\ dm = "proposer_setup"
                    /\ partner_state = "offered"
                    /\ partner_state' = "bootstrapped"
                    /\ UNCHANGED << proposer_state, dm, escrows, timelocks >>

PartnerConfirmAddress == /\ partner_state = "bootstrapped"
                         /\ partner_state' = "pendinglock"
                         /\ dm' = "partner_address"
                         /\ UNCHANGED << proposer_state, escrows, timelocks >>

ProposerConfirmAddress == /\ proposer_state = "bootstrapped"
                          /\ dm = "partner_address"
                          /\ proposer_state' = "pendinglock"
                          /\ dm' = "proposer_address"
                          /\ UNCHANGED  << partner_state, escrows, timelocks >>

PartnerDeposit == /\ partner_state = "pendinglock"
                  /\ dm = "proposer_address"
                  /\ partner_escrow' = "pending_deposit"
                  /\ partner_state' = "deposited"
                  /\ UNCHANGED << proposer_state, dm, proposer_escrow, timelocks >>

ProposerDeposit == /\ proposer_state = "pendinglock"
                   /\ partner_escrow = "confirmed_deposit"
                   /\ proposer_state' = "deposited"
                   /\ proposer_escrow' = "pending_deposit"
                   /\ UNCHANGED << partner_state, dm, partner_escrow, timelocks >>

RevealPreimage == /\ partner_state = "deposited"
                  /\ proposer_escrow = "confirmed_deposit"
                  /\ partner_escrow = "confirmed_deposit"
                  /\ TimelocksOk
                  /\ dm' = "preimage"
                  /\ partner_state' = "preimagerevealed"
                  /\ UNCHANGED << proposer_state, escrows, timelocks >>
                  
ReceivePreimage == /\ dm = "preimage"
                   /\ proposer_state \notin {"closable", "closed", "closedtimelock"}
                   /\ proposer_state' = "preimagerevealed"
                   /\ UNCHANGED << partner_state, escrows, dm, timelocks >>

SendProposerSeckey ==  /\ proposer_state = "preimagerevealed"
                       /\ proposer_escrow = "confirmed_deposit"
                       /\ partner_escrow = "confirmed_deposit"
                       /\ TimelocksOk
                       /\ dm' = "proposer_seckey"
                       /\ proposer_state' = "seckeyrevealed"
                       /\ UNCHANGED  << partner_state, escrows, timelocks >>

ReceiveProposerSecKey == /\ dm = "proposer_seckey"
                         /\ proposer_escrow = "confirmed_deposit"
                         /\ partner_escrow = "confirmed_deposit"
                         /\ TimelocksOk
                         /\ partner_state' = "seckeyrevealed"
                         /\ dm' = "partner_seckey"
                         /\ UNCHANGED  << proposer_state, escrows, timelocks >>

ReceivePartnerSecKey == /\ dm = "partner_seckey"
                        /\ partner_escrow = "confirmed_deposit"
                        /\ TimelocksOk
                        /\ proposer_state' = "closable"
                        /\ UNCHANGED << partner_state, dm, escrows, timelocks >>

ProtocolAction == \/ ProposeSwap
                  \/ OfferSwap
                  \/ RespondToOffer
                  \/ PartnerBootstrap
                  \/ PartnerConfirmAddress
                  \/ ProposerConfirmAddress
                  \/ PartnerDeposit
                  \/ ProposerDeposit
                  \/ RevealPreimage
                  \/ ReceivePreimage
                  \/ SendProposerSeckey
                  \/ ReceiveProposerSecKey
                  \/ ReceivePartnerSecKey

(*
 * Spending from escrows
 *)

 \* Anytime after funds have been deposited, we assume that the protocol can
 \* stall for a while and then either participant can take the refund of their
 \* escrow.
ProposerSpendRefund ==  /\ proposer_escrow = "confirmed_deposit"
                        /\ proposer_timelock_mature = TRUE
                        /\ proposer_escrow' = "pending_refund"
                        /\ UNCHANGED << participant_states, dm, partner_escrow, timelocks >>

ProposerReceiveRefund == /\ proposer_escrow = "confirmed_refund"
                         /\ proposer_state' = "closedtimelock"
                         /\ UNCHANGED << partner_state, dm, escrows, timelocks >>

PartnerSpendRefund == /\ partner_escrow = "confirmed_deposit"
                      /\ partner_timelock_mature = TRUE
                      /\ partner_escrow' = "pending_refund"
                      /\ UNCHANGED << participant_states, dm, proposer_escrow, timelocks >>

PartnerReceiveRefund ==  /\ partner_escrow = "confirmed_refund"
                         /\ partner_state' = "closedtimelock"
                         /\ UNCHANGED << proposer_state, dm, escrows, timelocks >>
                         
RefundAction == \/ ProposerSpendRefund
                \/ ProposerReceiveRefund                 
                \/ PartnerSpendRefund
                \/ PartnerReceiveRefund

\* Once a participant knows the hash preimage, they can spend via the hashlock
\* It's better for privacy to wait until they can do a keyspend, but its possible
\* and makes sure that everyone gets paid if the protocol stops there.
\* the Partner starts off with the preimage, so they can spend as soon as funds
\* are locked.
PartnerSpendHashlock == /\ proposer_escrow = "confirmed_deposit"
                        /\ TimelocksOk
                        \* The partner spends the proposer escrow
                        /\ proposer_escrow' = "pending_spend"
                        \* TODO: change state for partner?
                        /\ UNCHANGED << partner_escrow, participant_states, timelocks, dm >>

ProposerObservesPreimageOnchain == /\ proposer_escrow = "confirmed_spend"
                                   /\ proposer_state # "closable"
                                   /\ proposer_state' = "preimagerevealed"
                                   /\ UNCHANGED << partner_state, escrows, timelocks, dm >>

\* Proposer can spend from the hashlock as soon as the preimage is revealed, either
\* through the protocol or because they saw the Partner spend with it onchain.
\* The Proposer spends the partner escrow.
ProposerSpendHashLock == /\ partner_escrow = "confirmed_deposit"
                         /\ TimelocksOk
                         /\ proposer_state = "preimagerevealed"
                         /\ partner_escrow' = "pending_spend"
                         /\ UNCHANGED << proposer_escrow, participant_states, timelocks, dm >>

HashlockAction == PartnerSpendHashlock \/ ProposerObservesPreimageOnchain \/ ProposerSpendHashLock

\* The best case is where the participants spend via the keypath.
PartnerSpendKeypath == /\ proposer_escrow = "confirmed_deposit"
                       /\ TimelocksOk
                       /\ partner_state = "seckeyrevealed"
                       /\ proposer_escrow' = "pending_spend"
                       /\ UNCHANGED << partner_escrow, participant_states, timelocks, dm >>

ProposerSpendKeypath == /\ partner_escrow = "confirmed_deposit"
                        /\ TimelocksOk
                        /\ proposer_state = "closable"
                        /\ partner_escrow' = "pending_spend"
                        /\ UNCHANGED << proposer_escrow, participant_states, timelocks, dm >>

KeypathSpendAction == PartnerSpendKeypath \/ ProposerSpendKeypath

\* Partner spends the proposer escrow
PartnerFinished == /\ proposer_escrow = "confirmed_spend"
                   /\ partner_state' = "closed"
                   /\ UNCHANGED << proposer_state, escrows, timelocks, dm >>

\* Proposer spends the proposer escrow
ProposerFinished == /\ partner_escrow = "confirmed_spend"
                    /\ proposer_state' = "closed"
                    /\ UNCHANGED << partner_state, escrows, timelocks, dm >>

TerminalAction == PartnerFinished \/ ProposerFinished

(*
 * Cancellation
 *)

 PartnerCancel == /\ dm = "cancel_swap"
                  /\ partner_state = "offered"
                  /\ partner_state' = "cancelled"
                  /\ UNCHANGED << proposer_state, dm, escrows, timelocks >>

(*
 * Blockchain advancing
 *)
BlockConfirmation == \/  /\  \/  /\ partner_escrow  = "pending_deposit"
                                 /\ partner_escrow' = "confirmed_deposit"
                             \/  /\ partner_escrow  = "pending_refund"
                                 /\ partner_escrow' = "confirmed_refund"
                             \/  /\ partner_escrow  = "pending_spend"
                                 /\ partner_escrow' = "confirmed_spend"
                         /\ UNCHANGED << participant_states, dm, proposer_escrow, timelocks >>
                     \/  /\  \/  /\ proposer_escrow  = "pending_deposit"
                                 /\ proposer_escrow' = "confirmed_deposit"
                             \/  /\ proposer_escrow  = "pending_refund"
                                 /\ proposer_escrow' = "confirmed_refund"
                             \/  /\ proposer_escrow  = "pending_spend"
                                 /\ proposer_escrow' = "confirmed_spend"
                         /\ UNCHANGED << participant_states, dm, partner_escrow, timelocks >>

\* Some amount of time after an escrow has been confirmed, the timelock 
\* will mature. 
\* It is an important safety property that the proposer timelock
\* matures first. 
ProposerTimelockMature == /\ proposer_timelock_mature = FALSE
                          /\ partner_timelock_mature = FALSE
                          /\ proposer_escrow = "confirmed_deposit"
                          /\ proposer_timelock_mature' = TRUE
                          /\ UNCHANGED << participant_states, dm, escrows, partner_timelock_mature >>

PartnerTimelockMature == /\ proposer_timelock_mature = TRUE
                         /\ partner_escrow = "confirmed_deposit"
                         /\ partner_timelock_mature' = TRUE
                         /\ UNCHANGED << participant_states, dm, escrows, proposer_timelock_mature >>

TimelockMaturation == ProposerTimelockMature \/ PartnerTimelockMature

(*
 * Invariants and Temporal Properties
 *)

\* At the time when both parties have deposited to their escrows, the partner has
\* the hashlock preimage, but the proposer does not. The partner could wait until 
\* right before their refund timelock matures and then take the proposer escrow via
\* hashlock and take their own refund via the timelock. Therefor it is critically
\* important that the proposer timelock matures FIRST, so that they can get their money
\* back if the partner is holding back the preimage
ProposerGetsRefundFirst == partner_timelock_mature => proposer_timelock_mature

\* If one participant gets their refund, they do not also get to spend the other escrow.
\* A refund of one participant always leads to a refund of the other. 
\* A hashlock or keypath spend of one participant always leads to a spend of the other.
\* In other words, they can't steal money from the other participant.
NobodyGetsBothEscrows == \/ ProposerRefund ~> PartnerRefund
                         \/ PartnerRefund ~> ProposerRefund
                         \/ ProposerPaid ~> PartnerPaid
                         \/ PartnerPaid ~> ProposerPaid

\* Once funds have been deposited, they eventually get paid out. 
\* Once an escrow has been paid out, it doesn't get re-spent
EscrowPaymentTerminal == /\ proposer_state = "deposited" ~> ( (<>[] PartnerPaid) \/ (<>[] ProposerRefund) )
                         /\ partner_state = "deposited" ~> ( (<>[] ProposerPaid) \/ (<>[] PartnerRefund) )

Next == \/ BlockConfirmation
        \/ ProtocolAction
        \/ RefundAction
        \/ TimelockMaturation
        \/ HashlockAction
        \/ KeypathSpendAction
        \/ TerminalAction
        \/ PartnerCancel

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

=============================================================================

Assumptions that we make in this spec:
1. Participants try to make forward progress for themselves. We don't model the case where someone just leaves their money behind.
2. Transactions submitted to the Bitcoin are eventually mined. We assume that participant software will rebroadcast purged transactions. 
3. We assume that participants can get their transactions into the next block through fee selection or fee bumping
4. We assume that both participants watch the chain and see when transactions happen.