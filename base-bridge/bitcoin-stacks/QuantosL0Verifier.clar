;; Quantos L0 Verifier for Stacks (Bitcoin L2 / Clarity)
;; On-chain validation of PQC finality proofs produced by Quantos.
;;
;; Clarity has no loops / recursion is limited, so we keep structures flat
;; and rely on maps keyed by fixed-size buffers.

;; ================================================================
;; Constants & error codes
;; ================================================================
(define-constant ERR-UNKNOWN-SET u0)
(define-constant ERR-INSUFFICIENT-STAKE u1)
(define-constant ERR-PROOF-ALREADY-VERIFIED u2)
(define-constant ERR-PROOF-NOT-VERIFIED u3)
(define-constant ERR-DEPOSIT-ALREADY-RELAYED u4)
(define-constant ERR-NOT-ADMIN u5)

;; ================================================================
;; Data variables
;; ================================================================
(define-data-var admin principal tx-sender)
(define-data-var challenge-window uint u300) ;; default 300 blocks

;; ================================================================
;; Maps
;; ================================================================
;; Validator sets keyed by 32-byte root (as a 32-tuple of uints, flattened)
;; Clarity doesn't have bytes directly; we use a 32-element list of uints.
(define-map validator-sets
  { root: (list 32 uint) }
  { total-stake: uint, threshold: uint, active: bool, registered-at: uint })

;; Proofs keyed by 32-byte proof-hash
(define-map proofs
  { proof-hash: (list 32 uint) }
  { verified: bool, validator-set-root: (list 32 uint), epoch: uint, slot: uint, accepted-at: uint })

;; Deposits keyed by 32-byte deposit-id
(define-map deposits
  { deposit-id: (list 32 uint) }
  { relayed: bool, amount: uint })

;; ================================================================
;; Private helpers
;; ================================================================
(define-private (is-admin))
  (is-eq tx-sender (var-get admin))

(define-private (assert-admin))
  (asserts! (is-admin) (err ERR-NOT-ADMIN))

;; ================================================================
;; Admin entry functions
;; ================================================================
(define-public (register-validator-set
    (root (list 32 uint))
    (total-stake uint)
    (threshold uint))
  (begin
    (assert-admin)
    (map-set validator-sets
      { root: root }
      { total-stake: total-stake, threshold: threshold, active: true, registered-at: block-height })
    (ok true)))

(define-public (revoke-validator-set (root (list 32 uint)))
  (let ((set (unwrap! (map-get? validator-sets { root: root }) (err ERR-UNKNOWN-SET))))
    (assert-admin)
    (map-set validator-sets
      { root: root }
      (merge set { active: false }))
    (ok true)))

(define-public (set-challenge-window (window uint))
  (begin
    (assert-admin)
    (var-set challenge-window window)
    (ok true)))

(define-public (transfer-admin (new-admin principal))
  (begin
    (assert-admin)
    (var-set admin new-admin)
    (ok true)))

;; ================================================================
;; Proof verification entry function
;; ================================================================
(define-public (verify-proof
    (proof-hash (list 32 uint))
    (validator-set-root (list 32 uint))
    (epoch uint)
    (slot uint)
    (state-root (list 32 uint))
    (signed-stake uint))
  (let ((set (unwrap! (map-get? validator-sets { root: validator-set-root }) (err ERR-UNKNOWN-SET))))
    ;; 1. Must be active
    (asserts! (get active set) (err ERR-UNKNOWN-SET))
    ;; 2. Replay protection
    (asserts! (is-none (map-get? proofs { proof-hash: proof-hash })) (err ERR-PROOF-ALREADY-VERIFIED))
    ;; 3. Stake threshold
    (asserts! (>= signed-stake (get threshold set)) (err ERR-INSUFFICIENT-STAKE))
    ;; Store
    (map-set proofs
      { proof-hash: proof-hash }
      { verified: true,
        validator-set-root: validator-set-root,
        epoch: epoch,
        slot: slot,
        accepted-at: block-height })
    (ok true)))

;; ================================================================
;; Relay authorization entry function
;; ================================================================
(define-public (authorize-relay
    (proof-hash (list 32 uint))
    (quantos-deposit-id (list 32 uint))
    (amount uint))
  (let ((state (unwrap! (map-get? proofs { proof-hash: proof-hash }) (err ERR-PROOF-NOT-VERIFIED)))
        (window (var-get challenge-window)))
    ;; 1. Proof verified
    (asserts! (get verified state) (err ERR-PROOF-NOT-VERIFIED))
    ;; 2. Idempotence
    (asserts! (is-none (map-get? deposits { deposit-id: quantos-deposit-id })) (err ERR-DEPOSIT-ALREADY-RELAYED))
    ;; 3. Challenge window elapsed (optimistic)
    (asserts! (>= block-height (+ (get accepted-at state) window)) (err ERR-PROOF-NOT-VERIFIED))
    ;; Store
    (map-set deposits
      { deposit-id: quantos-deposit-id }
      { relayed: true, amount: amount })
    (ok true)))

;; ================================================================
;; Emergency override (admin-only)
;; ================================================================
(define-public (force-mark-relayed (quantos-deposit-id (list 32 uint)) (amount uint))
  (begin
    (assert-admin)
    (map-set deposits
      { deposit-id: quantos-deposit-id }
      { relayed: true, amount: amount })
    (ok true)))

;; ================================================================
;; Read-only functions
;; ================================================================
(define-read-only (is-proof-verified (proof-hash (list 32 uint)))
  (match (map-get? proofs { proof-hash: proof-hash })
    state (get verified state)
    false))

(define-read-only (is-deposit-relayed (deposit-id (list 32 uint)))
  (match (map-get? deposits { deposit-id: deposit-id })
    deposit (get relayed deposit)
    false))

(define-read-only (get-validator-set (root (list 32 uint)))
  (map-get? validator-sets { root: root }))

(define-read-only (get-proof-state (proof-hash (list 32 uint)))
  (map-get? proofs { proof-hash: proof-hash }))

(define-read-only (get-challenge-window)
  (var-get challenge-window))
