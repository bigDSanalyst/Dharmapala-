/-!
# Bounded revision debt: what the telescoping fix proves, and what it doesn't

Core Lean 4 only (no Mathlib). CI checks it with the Lean named in lean/lean-toolchain
(4.14.0): `lean lean/BoundedDebt.lean`.

A chain is written `s :: rest`; `chainCost c s rest` is the sum of step costs
along it, and the attachment's `totalDebtOfChain (s :: rest)` is
`D₀ + chainCost c s rest`.

§1  The attachment's `IsTelescoping`, transcribed literally (Φ : σ → ℕ, Lean's
    truncated `-`, quantified over all pairs). `total_debt_le_potential` is FALSE:
    a free uphill step recharges Φ, and the next step spends the recharge.
§2  Moving Φ to ℤ removes the truncation, but the all-pairs quantifier then
    forces Φ to be constant and every step cost to be 0: the class collapses into
    the "locally conservative" case the attachment itself calls vacuous.
§3  Corrected statement: quantify over the revision relation R only and write the
    condition additively. Proven, with the invariant
    debt spent + reserve left ≤ reserve at start.
    Plus two corollaries: any positive-cost cycle rules out every potential,
    and so does any infinite chain whose steps all cost ≥ 1.
§4  Terminating does not mean budgetable: lexicographic revisions on ℕ × ℕ are
    well-founded (every run has finite debt), yet no ℕ-valued potential exists.

The existence / impossibility pair (extension-only revision, fixed language;
a theory is identified with its set of completions):
§5  Finitely many completions ⇒ a finite reserve, for ANY finite number N of
    completions (no power-of-2 structure used).
    · Unit cost per commitment: reserve = survivors − 1, and it is the least
      reserve. n atoms (N = 2^n) ⇒ at most 2^n − 1 commitments.
    · Information cost (whole bits decided): reserve = ⌊log₂ survivors⌋.
      n atoms ⇒ at most n bits.
    · Replenishment: a granted atom doubles the survivors (+1 bit, r ↦ 2r + 1).
§6  Infinitely many completions ⇒ no reserve. Instances: infinitely many atoms;
    pure equality, where the chain is "there are ≥ k elements".
§7  Adjoining atoms as a free move of the system itself ⇒ no reserve.

Retraction (§8): state (S, k), k = retractions left; a retraction may undo any
commitments (strictly enlarge the surviving completions) at cost c.
§8a Generic: Ψ(S) + K·k telescopes when each retraction's cost PLUS the
    reserve it restores is ≤ K. Re-validation cost alone is not enough.
§8b Propositional, n atoms: K = n + c works and is tight. The least reserve at
    (all completions, k) is n + k(n + c), so each unit of allowance is worth
    exactly n + c bits of debt, and K = c provably fails.
§8c No allowance: retraction at ANY price leaves no reserve.
§8d Self-minting allowance at ANY price leaves no reserve.
    A price is not a ration: in both cases the price only adds to the debt.

Refinement (§9): a concrete append-only ledger (commit / retract, provenance
tags in a join-semilattice, allowance, recorded debt) with a decidable guard,
mapped onto §8 re-priced with exact reserve-drop costs (§9.0).
§9c Step simulation + debt domination for every accepted step; each commit
    records exactly the reserve it uses.
§9d Transfer: recorded debt grows by at most n + (n + c)·k₀ from any starting
    state; on commit-only runs spent + left = start holds with equality.
§9e The guard: never blocks a valid operation (so the preconditions do the
    restricting), is sufficient on its own for any step function, and for
    c ≥ 1 refuses ANY transition that raises the allowance (c = 0 shown to fail).
§9f Append-only log; recorded debt = sum of the log; cumProv is monotone,
    equals the join of the logged tags, and lies above every one of them.
-/

/-! ## §0 Chains -/

section Chains
variable {σ : Type}

/-- `s :: rest` is an `R`-chain. -/
def IsChainFrom (R : σ → σ → Prop) : σ → List σ → Prop
  | _, [] => True
  | a, b :: rest => R a b ∧ IsChainFrom R b rest

/-- Sum of step costs along `s :: rest`. -/
def chainCost (c : σ → σ → Nat) : σ → List σ → Nat
  | _, [] => 0
  | a, b :: rest => c a b + chainCost c b rest

/-- Last element of `s :: rest`. -/
def lastOf : σ → List σ → σ
  | s, [] => s
  | _, b :: rest => lastOf b rest

/-- The attachment's `totalDebtOfChain (s :: rest)`. -/
def totalDebt (c : σ → σ → Nat) (D₀ : Nat) (s : σ) (rest : List σ) : Nat :=
  D₀ + chainCost c s rest

end Chains

/-! ## §1 The definition as written is false in ℕ -/

namespace AsWritten

/-- Literal transcription: `stepCost s1 s2 ≤ Φ s1 - Φ s2` for *all* pairs,
    with `Φ : σ → ℕ`, so `-` is truncated subtraction. -/
def IsTelescoping {σ : Type} (c : σ → σ → Nat) (Φ : σ → Nat) : Prop :=
  ∀ s1 s2, c s1 s2 ≤ Φ s1 - Φ s2

/-- Where the sketched induction step breaks: `(Φ s - Φ s') + Φ s' = Φ s`
    fails in ℕ as soon as `Φ s' > Φ s`. -/
example : (0 - 10) + 10 ≠ 0 := by decide

/-- Free-recharge instance on two signatures. `false → true` is uphill:
    `Φ false - Φ true = 0 - 10 = 0` in ℕ, so a cost of 0 satisfies the hypothesis.
    `true → false` then spends the 10 that the free step put there. -/
def Φr : Bool → Nat := fun b => if b then 10 else 0
def cr : Bool → Bool → Nat := fun a b => if a && !b then 10 else 0

theorem recharge_satisfies_hypothesis : IsTelescoping cr Φr := by
  intro a b; cases a <;> cases b <;> decide

example : chainCost cr false [true, false, true, false] = 20 := by decide

/-- `total_debt_le_potential`, quantified over the data its proof sketch uses
    (any stepCost, any Φ, any D₀), is false. -/
theorem total_debt_le_potential_is_false :
    ¬ ∀ (c : Bool → Bool → Nat) (Φ : Bool → Nat) (D₀ : Nat),
        IsTelescoping c Φ →
        ∀ (s : Bool) (rest : List Bool), totalDebt c D₀ s rest ≤ Φ s + D₀ := by
  intro h
  have := h cr Φr 0 recharge_satisfies_hypothesis false [true, false]
  exact absurd this (by decide)

def roundTrips : Nat → List Bool
  | 0 => []
  | k + 1 => true :: false :: roundTrips k

theorem cost_roundTrips (k : Nat) : chainCost cr false (roundTrips k) = 10 * k := by
  induction k with
  | zero => rfl
  | succ k ih =>
    have e1 : cr false true = 0 := rfl
    have e2 : cr true false = 10 := rfl
    show cr false true + (cr true false + chainCost cr false (roundTrips k)) = 10 * (k + 1)
    rw [e1, e2, ih]
    omega

/-- Worse than a wrong constant: under the hypothesis as written, debt from a
    start with Φ = 0 is unbounded. -/
theorem unbounded_debt_under_hypothesis (n : Nat) :
    ∃ rest, n ≤ chainCost cr false rest :=
  ⟨roundTrips n, by rw [cost_roundTrips]; omega⟩

end AsWritten

/-! ## §2 In ℤ, the all-pairs quantifier makes it vacuous -/

namespace IntAllPairs

def IsTelescoping {σ : Type} (c : σ → σ → Nat) (Φ : σ → Int) : Prop :=
  ∀ s1 s2, (c s1 s2 : Int) ≤ Φ s1 - Φ s2

theorem forces_zero_cost {σ : Type} (c : σ → σ → Nat) (Φ : σ → Int)
    (h : IsTelescoping c Φ) : ∀ a b, c a b = 0 := by
  intro a b
  have h1 := h a b
  have h2 := h b a
  omega

theorem forces_constant {σ : Type} (c : σ → σ → Nat) (Φ : σ → Int)
    (h : IsTelescoping c Φ) : ∀ a b, Φ a = Φ b := by
  intro a b
  have h1 := h a b
  have h2 := h b a
  omega

end IntAllPairs

/-! ## §3 The corrected statement -/

namespace Corrected
variable {σ : Type}

/-- Telescoping, done right: only admissible revisions `R`, additive form
    (no truncated subtraction). Equivalently: Φ never increases along R, and
    every step is paid for by the drop in Φ. -/
def IsTelescoping (R : σ → σ → Prop) (c : σ → σ → Nat) (Φ : σ → Nat) : Prop :=
  ∀ s1 s2, R s1 s2 → c s1 s2 + Φ s2 ≤ Φ s1

/-- Invariant: debt spent + reserve left ≤ reserve at start. -/
theorem spent_plus_left_le (R : σ → σ → Prop) (c : σ → σ → Nat) (Φ : σ → Nat)
    (hΦ : IsTelescoping R c Φ) :
    ∀ (rest : List σ) (s : σ), IsChainFrom R s rest →
      chainCost c s rest + Φ (lastOf s rest) ≤ Φ s := by
  intro rest
  induction rest with
  | nil => intro s _; simp [chainCost, lastOf]
  | cons t rest ih =>
    intro s h
    have h' : R s t ∧ IsChainFrom R t rest := h
    have h1 := hΦ s t h'.1
    have h2 := ih t h'.2
    show c s t + chainCost c t rest + Φ (lastOf t rest) ≤ Φ s
    omega

/-- The attachment's theorem, with its hypothesis repaired. -/
theorem total_debt_le_potential (R : σ → σ → Prop) (c : σ → σ → Nat) (Φ : σ → Nat)
    (D₀ : Nat) (hΦ : IsTelescoping R c Φ) (s : σ) (rest : List σ)
    (hchain : IsChainFrom R s rest) :
    totalDebt c D₀ s rest ≤ Φ s + D₀ := by
  have := spent_plus_left_le R c Φ hΦ rest s hchain
  unfold totalDebt
  omega

/-- The repaired hypothesis rejects the §1 recharge system outright. -/
theorem recharge_has_no_potential :
    ¬ ∃ Φ : Bool → Nat, IsTelescoping (fun _ _ => True) AsWritten.cr Φ := by
  intro ⟨Φ, hΦ⟩
  have h1 := hΦ false true trivial
  have h2 := hΦ true false trivial
  have e1 : AsWritten.cr false true = 0 := rfl
  have e2 : AsWritten.cr true false = 10 := rfl
  omega

/-- Any cycle with positive total cost rules out every potential.
    (On a finite signature space the converse holds too: a potential exists iff
    no positive-cost cycle, the longest-path form of the feasible-potential theorem.)
    Instance: if a dimension-preserving, invertible re-scoping costs anything,
    then s → s' → s is such a cycle. -/
theorem costly_cycle_kills_potential (R : σ → σ → Prop) (c : σ → σ → Nat)
    (s : σ) (rest : List σ) (hchain : IsChainFrom R s rest)
    (hcycle : lastOf s rest = s) (hpos : 0 < chainCost c s rest) :
    ¬ ∃ Φ, IsTelescoping R c Φ := by
  intro ⟨Φ, hΦ⟩
  have := spent_plus_left_le R c Φ hΦ rest s hchain
  rw [hcycle] at this
  omega

/-- Any infinite chain whose steps all cost ≥ 1 rules out every potential.
    This is the whole content of the first-order impossibility example; the logic
    only has to supply the chain (e.g. T_n = {"there are ≥ k elements" : k ≤ n}
    over the empty language; no Gödel needed). -/
theorem infinite_costly_chain_kills_potential (R : σ → σ → Prop) (c : σ → σ → Nat)
    (f : Nat → σ) (hstep : ∀ n, R (f n) (f (n + 1)))
    (hcost : ∀ n, 1 ≤ c (f n) (f (n + 1))) :
    ¬ ∃ Φ, IsTelescoping R c Φ := by
  intro ⟨Φ, hΦ⟩
  have key : ∀ n, Φ (f n) + n ≤ Φ (f 0) := by
    intro n
    induction n with
    | zero => omega
    | succ n ih =>
      have h1 := hΦ (f n) (f (n + 1)) (hstep n)
      have h2 := hcost n
      omega
  have := key (Φ (f 0) + 1)
  omega

end Corrected

/-! ## §4 Terminating ≠ budgetable

States (a, b): a = major axis, b = minor refinements. A major revision lowers a
and may reset b to anything; a minor revision lowers b. Each revision costs 1.
Every run terminates (lexicographic order on ℕ × ℕ is a well-order of type ω²,
and in particular a WQO), so every run's debt is finite. But
(1,0) → (0,N) → (0,N-1) → … → (0,0) costs N + 1 for every N, so no reserve
fixed in advance covers (1,0). The ordinal Φ(a, b) = ω·a + b works;
no ℕ-valued Φ does. -/

namespace Lex

def Step (x y : Nat × Nat) : Prop := y.1 < x.1 ∨ (y.1 = x.1 ∧ y.2 < x.2)

/-- Every run terminates. -/
theorem step_wf : WellFounded (fun y x => Step x y) := by
  have hlex : WellFounded (Prod.Lex (α := Nat) (β := Nat) (· < ·) (· < ·)) :=
    (Prod.lex ⟨_, Nat.lt_wfRel.wf⟩ ⟨_, Nat.lt_wfRel.wf⟩).wf
  apply Subrelation.wf (h₂ := hlex)
  intro y x h
  rcases y with ⟨a', b'⟩
  rcases x with ⟨a, b⟩
  cases h with
  | inl h => exact Prod.Lex.left _ _ h
  | inr h =>
    obtain ⟨h1, h2⟩ := h
    simp only at h1 h2
    subst h1
    exact Prod.Lex.right _ h2

/-- …but no ℕ-valued reserve covers it. -/
theorem no_nat_potential :
    ¬ ∃ Φ : Nat × Nat → Nat, Corrected.IsTelescoping Step (fun _ _ => 1) Φ := by
  intro ⟨Φ, hΦ⟩
  have col : ∀ k, k ≤ Φ (0, k) := by
    intro k
    induction k with
    | zero => exact Nat.zero_le _
    | succ k ih =>
      have := hΦ (0, k + 1) (0, k) (Or.inr ⟨rfl, Nat.lt_succ_self k⟩)
      dsimp only at this
      omega
  have h1 := hΦ (1, 0) (0, Φ (1, 0)) (Or.inl Nat.zero_lt_one)
  dsimp only at h1
  have h2 := col (Φ (1, 0))
  omega

end Lex

/-! ## §5 Finitely many completions: a finite reserve exists

A theory over a fixed language is identified with its set of completions; for
propositional logic over n atoms these are its satisfying valuations, numbered
0 … 2^n − 1. Completions are numbered below N and `S v = true` means completion
v survives. A consistent non-conservative extension in the same language is a
strict shrink that keeps at least one completion. (When N is finite, every set
of completions is the completion set of some theory, so nothing is lost.)

Only the final bit bound uses N = 2^n. The reserve exists for every finite N,
e.g. N = 3: "there are exactly 1, 2 or 3 elements" in pure equality. -/

namespace FiniteCompletions

/-- Surviving completions among 0, …, k − 1. -/
def count (S : Nat → Bool) : Nat → Nat
  | 0 => 0
  | k + 1 => count S k + (if S k then 1 else 0)

theorem count_succ_true (S : Nat → Bool) (k : Nat) (h : S k = true) :
    count S (k + 1) = count S k + 1 := by simp [count, h]

theorem count_succ_false (S : Nat → Bool) (k : Nat) (h : S k = false) :
    count S (k + 1) = count S k := by simp [count, h]

theorem count_le (S : Nat → Bool) : ∀ k, count S k ≤ k := by
  intro k
  induction k with
  | zero => simp [count]
  | succ k ih =>
    cases h : S k with
    | false => rw [count_succ_false S k h]; omega
    | true => rw [count_succ_true S k h]; omega

theorem count_mono (S S' : Nat → Bool) :
    ∀ k, (∀ v, v < k → S' v = true → S v = true) → count S' k ≤ count S k := by
  intro k
  induction k with
  | zero => intro _; simp [count]
  | succ k ih =>
    intro hsub
    have ih' := ih (fun v hv => hsub v (Nat.lt_succ_of_lt hv))
    have hk := hsub k (Nat.lt_succ_self k)
    cases h' : S' k with
    | false =>
      rw [count_succ_false S' k h']
      cases h : S k with
      | false => rw [count_succ_false S k h]; exact ih'
      | true => rw [count_succ_true S k h]; omega
    | true =>
      rw [count_succ_true S' k h', count_succ_true S k (hk h')]
      omega

/-- A strict shrink loses at least one completion. -/
theorem count_strict (S S' : Nat → Bool) :
    ∀ k, (∀ v, v < k → S' v = true → S v = true) →
      (∃ v, v < k ∧ S v = true ∧ S' v = false) → count S' k + 1 ≤ count S k := by
  intro k
  induction k with
  | zero => intro _ ⟨v, hv, _⟩; exact absurd hv (Nat.not_lt_zero v)
  | succ k ih =>
    intro hsub ⟨v, hv, hSv, hS'v⟩
    have hsub' : ∀ w, w < k → S' w = true → S w = true :=
      fun w hw => hsub w (Nat.lt_succ_of_lt hw)
    have hk := hsub k (Nat.lt_succ_self k)
    by_cases hvk : v = k
    · rw [hvk] at hSv hS'v
      have hmono := count_mono S S' k hsub'
      rw [count_succ_false S' k hS'v, count_succ_true S k hSv]
      omega
    · have ih' := ih hsub' ⟨v, by omega, hSv, hS'v⟩
      cases h' : S' k with
      | false =>
        rw [count_succ_false S' k h']
        cases h : S k with
        | false => rw [count_succ_false S k h]; exact ih'
        | true => rw [count_succ_true S k h]; omega
      | true =>
        rw [count_succ_true S' k h', count_succ_true S k (hk h')]
        omega

theorem count_pos (S : Nat → Bool) :
    ∀ k, (∃ v, v < k ∧ S v = true) → 1 ≤ count S k := by
  intro k
  induction k with
  | zero => intro ⟨v, hv, _⟩; exact absurd hv (Nat.not_lt_zero v)
  | succ k ih =>
    intro ⟨v, hv, hSv⟩
    by_cases hvk : v = k
    · rw [hvk] at hSv
      rw [count_succ_true S k hSv]
      omega
    · have ih' := ih ⟨v, by omega, hSv⟩
      cases h : S k with
      | false => rw [count_succ_false S k h]; exact ih'
      | true => rw [count_succ_true S k h]; omega

/-- Consistent non-conservative extension: drop ≥ 1 completion, keep ≥ 1. -/
def Shrink (N : Nat) (S S' : Nat → Bool) : Prop :=
  (∀ v, v < N → S' v = true → S v = true) ∧
  (∃ v, v < N ∧ S v = true ∧ S' v = false) ∧
  (∃ v, v < N ∧ S' v = true)

/-! ### Unit cost: count commitments -/

/-- Reserve = commitments still possible = surviving completions − 1.
    This is the undecided side; committed = (start − 1) − reserve goes UP with
    each commitment, so it cannot be the potential. -/
def reserve (N : Nat) (S : Nat → Bool) : Nat := count S N - 1

/-- The reserve telescopes. The cost is 1 per commitment and is not defined
    from the reserve; the content is that a strict shrink loses a completion. -/
theorem reserve_telescopes (N : Nat) :
    Corrected.IsTelescoping (Shrink N) (fun _ _ => 1) (reserve N) := by
  intro S S' h
  obtain ⟨hsub, hdrop, hne⟩ := h
  have h1 := count_strict S S' N hsub hdrop
  have h2 := count_pos S' N hne
  show 1 + (count S' N - 1) ≤ count S N - 1
  omega

/-- Any chain makes at most N − 1 commitments; n atoms (N = 2^n) ⇒ ≤ 2^n − 1. -/
theorem commitments_le (N : Nat) (S : Nat → Bool) (rest : List (Nat → Bool))
    (h : IsChainFrom (Shrink N) S rest) : chainCost (fun _ _ => 1) S rest ≤ N - 1 := by
  have h1 := Corrected.spent_plus_left_le (Shrink N) (fun _ _ => 1) (reserve N)
    (reserve_telescopes N) rest S h
  have h2 := count_le S N
  unfold reserve at h1
  omega

/-- Completions j, j+1, …: dropping one completion at a time. `tail 0` is the
    set of all completions. -/
def tail (j : Nat) : Nat → Bool := fun v => decide (j ≤ v)

theorem tail_step (N j : Nat) (h : j + 1 < N) : Shrink N (tail j) (tail (j + 1)) := by
  refine ⟨?_, ?_, ?_⟩
  · intro v _ hv
    simp [tail] at hv ⊢
    omega
  · exact ⟨j, by omega, by simp [tail], by simp [tail]⟩
  · exact ⟨j + 1, h, by simp [tail]⟩

/-- It is the least reserve: every reserve at the full set is ≥ N − 1. -/
theorem reserve_is_least (N : Nat) (Φ : (Nat → Bool) → Nat)
    (hΦ : Corrected.IsTelescoping (Shrink N) (fun _ _ => 1) Φ) :
    N - 1 ≤ Φ (tail 0) := by
  have key : ∀ d j, j + d + 1 = N → d ≤ Φ (tail j) := by
    intro d
    induction d with
    | zero => intro _ _; exact Nat.zero_le _
    | succ d ih =>
      intro j hj
      have h1 := hΦ (tail j) (tail (j + 1)) (tail_step N j (by omega))
      have h2 := ih (j + 1) (by omega)
      dsimp only at h1
      omega
  cases N with
  | zero => exact Nat.zero_le _
  | succ n =>
    have := key n 0 (by omega)
    omega

/-! ### Information cost: count bits -/

theorem log2_div_add (m m' : Nat) (h1 : 1 ≤ m') (h2 : m' ≤ m) :
    Nat.log2 (m / m') + Nat.log2 m' ≤ Nat.log2 m := by
  have hq : 1 ≤ m / m' := (Nat.le_div_iff_mul_le (by omega)).2 (by omega)
  have e1 := Nat.log2_self_le (n := m / m') (by omega)
  have e2 := Nat.log2_self_le (n := m') (by omega)
  have e3 := Nat.div_mul_le_self m m'
  have key : 2 ^ (Nat.log2 (m / m') + Nat.log2 m') ≤ m := by
    rw [Nat.pow_add]
    exact Nat.le_trans (Nat.mul_le_mul e1 e2) e3
  by_cases hc : Nat.log2 m < Nat.log2 (m / m') + Nat.log2 m'
  · have := (Nat.log2_lt (n := m) (by omega)).1 hc
    omega
  · omega

/-- Whole bits a commitment decides: ⌊log₂ (survivors before / survivors after)⌋. -/
def bitCost (N : Nat) (S S' : Nat → Bool) : Nat := Nat.log2 (count S N / count S' N)

/-- Undecided bits: ⌊log₂ survivors⌋. -/
def bits (N : Nat) (S : Nat → Bool) : Nat := Nat.log2 (count S N)

theorem bits_telescope (N : Nat) :
    Corrected.IsTelescoping (Shrink N) (bitCost N) (bits N) := by
  intro S S' h
  obtain ⟨hsub, hdrop, hne⟩ := h
  have h1 := count_strict S S' N hsub hdrop
  have h2 := count_pos S' N hne
  exact log2_div_add (count S N) (count S' N) h2 (by omega)

/-- With n atoms, the bits decided along any chain total at most n. -/
theorem bits_spent_le (n : Nat) (S : Nat → Bool) (rest : List (Nat → Bool))
    (h : IsChainFrom (Shrink (2 ^ n)) S rest) :
    chainCost (bitCost (2 ^ n)) S rest ≤ n := by
  have h1 := Corrected.spent_plus_left_le (Shrink (2 ^ n)) (bitCost (2 ^ n))
    (bits (2 ^ n)) (bits_telescope (2 ^ n)) rest S h
  have h2 : bits (2 ^ n) S ≤ n := by
    unfold bits
    have hc := count_le S (2 ^ n)
    by_cases h0 : count S (2 ^ n) = 0
    · rw [h0, Nat.log2_zero]; exact Nat.zero_le n
    · have hlt : count S (2 ^ n) < 2 ^ (n + 1) := by
        have e : 2 ^ (n + 1) = 2 ^ n * 2 := Nat.pow_succ 2 n
        have := Nat.two_pow_pos n
        omega
      have := (Nat.log2_lt h0).2 hlt
      omega
  omega

/-! ### Replenishment: what one granted atom buys -/

theorem count_shift (T : Nat → Bool) (a : Nat) :
    ∀ j, count T (a + j) = count T a + count (fun v => T (a + v)) j := by
  intro j
  induction j with
  | zero => simp [count]
  | succ j ih =>
    show count T (a + j) + (if T (a + j) then 1 else 0) =
      count T a + (count (fun v => T (a + v)) j + (if T (a + j) then 1 else 0))
    rw [ih]
    omega

theorem count_congr (T T' : Nat → Bool) :
    ∀ k, (∀ v, v < k → T v = T' v) → count T k = count T' k := by
  intro k
  induction k with
  | zero => intro _; rfl
  | succ k ih =>
    intro h
    show count T k + (if T k then 1 else 0) = count T' k + (if T' k then 1 else 0)
    rw [ih (fun v hv => h v (Nat.lt_succ_of_lt hv)), h k (Nat.lt_succ_self k)]

/-- Adjoining a fresh atom (conservative: each survivor extends both ways)
    doubles the survivors, so the unit-cost reserve goes r ↦ 2r + 1. -/
theorem adjoin_doubles (S : Nat → Bool) (n : Nat) :
    count (fun v => S (v % 2 ^ n)) (2 ^ (n + 1)) = 2 * count S (2 ^ n) := by
  have e : 2 ^ (n + 1) = 2 ^ n + 2 ^ n := by rw [Nat.pow_succ]; omega
  rw [e]
  have hs := count_shift (fun v => S (v % 2 ^ n)) (2 ^ n) (2 ^ n)
  have c1 : count (fun v => S (v % 2 ^ n)) (2 ^ n) = count S (2 ^ n) :=
    count_congr _ _ _ (fun v hv => by simp [Nat.mod_eq_of_lt hv])
  have c2 : count (fun v => S ((2 ^ n + v) % 2 ^ n)) (2 ^ n) = count S (2 ^ n) :=
    count_congr _ _ _ (fun v hv => by simp [Nat.add_mod_left, Nat.mod_eq_of_lt hv])
  omega

theorem log2_double (c : Nat) (h : 1 ≤ c) : Nat.log2 (2 * c) = Nat.log2 c + 1 := by
  have h0 : c ≠ 0 := by omega
  have h2c : 2 * c ≠ 0 := by omega
  have e1 := Nat.log2_self_le h0
  have e2 : c < 2 ^ (Nat.log2 c + 1) := (Nat.log2_lt h0).1 (Nat.lt_succ_self _)
  have p1 : 2 ^ (Nat.log2 c + 1) = 2 ^ Nat.log2 c * 2 := Nat.pow_succ 2 _
  have p2 : 2 ^ (Nat.log2 c + 1 + 1) = 2 ^ (Nat.log2 c + 1) * 2 := Nat.pow_succ 2 _
  have hlt : Nat.log2 (2 * c) < Nat.log2 c + 1 + 1 := (Nat.log2_lt h2c).2 (by omega)
  have hge : ¬ Nat.log2 (2 * c) < Nat.log2 c + 1 := fun hc => by
    have := (Nat.log2_lt h2c).1 hc
    omega
  omega

/-- …and adds exactly one undecided bit. -/
theorem adjoin_adds_one_bit (S : Nat → Bool) (n : Nat) (h : 1 ≤ count S (2 ^ n)) :
    bits (2 ^ (n + 1)) (fun v => S (v % 2 ^ n)) = bits (2 ^ n) S + 1 := by
  unfold bits
  rw [adjoin_doubles]
  exact log2_double _ h

end FiniteCompletions

/-! ## §6 Infinitely many completions: no reserve

Here a "theory" is any set of completions. If there are infinitely many
completions (an injection f : ℕ → C), ruling them out one at a time is an
infinite chain of consistent non-conservative extensions, each costing 1.

The chain consists of genuine theories in both instances below, so the
impossibility transfers to them:
· infinitely many atoms: rule out the single-atom valuations one by one;
· pure equality: completions are indexed by cardinality (`some k` = exactly
  k + 1 elements, `none` = infinite), and `avoid some k` is the completion set
  of "there are ≥ k + 1 elements". What makes this case infinite is equality:
  it lets sentences count. Monadic logic without equality over finitely many
  predicates has finitely many completions, so §5 applies to it. -/

namespace InfiniteCompletions
variable {C : Type}

def ShrinkP (S S' : C → Prop) : Prop :=
  (∀ c, S' c → S c) ∧ (∃ c, S c ∧ ¬ S' c) ∧ (∃ c, S' c)

/-- Completions surviving after f 0, …, f (k − 1) are ruled out. -/
def avoid (f : Nat → C) (k : Nat) : C → Prop := fun c => ∀ i, i < k → c ≠ f i

theorem avoid_step (f : Nat → C) (hf : ∀ i j, f i = f j → i = j) (k : Nat) :
    ShrinkP (avoid f k) (avoid f (k + 1)) := by
  refine ⟨?_, ?_, ?_⟩
  · intro c hc i hi
    exact hc i (Nat.lt_succ_of_lt hi)
  · refine ⟨f k, ?_, ?_⟩
    · intro i hi heq
      have := hf k i heq
      omega
    · intro h
      exact h k (Nat.lt_succ_self k) rfl
  · refine ⟨f (k + 1), ?_⟩
    intro i hi heq
    have := hf (k + 1) i heq
    omega

theorem no_reserve (f : Nat → C) (hf : ∀ i j, f i = f j → i = j) :
    ¬ ∃ Φ : (C → Prop) → Nat, Corrected.IsTelescoping ShrinkP (fun _ _ => 1) Φ :=
  Corrected.infinite_costly_chain_kills_potential ShrinkP (fun _ _ => 1) (avoid f)
    (avoid_step f hf) (fun _ => Nat.le_refl 1)

/-- Infinitely many atoms: valuations ℕ → Bool. -/
def single (k : Nat) : Nat → Bool := fun i => decide (i = k)

theorem single_inj : ∀ i j, single i = single j → i = j := by
  intro i j h
  have := congrFun h i
  simp [single] at this
  omega

theorem infinitely_many_atoms_no_reserve :
    ¬ ∃ Φ : ((Nat → Bool) → Prop) → Nat,
      Corrected.IsTelescoping ShrinkP (fun _ _ => 1) Φ :=
  no_reserve single single_inj

/-- Pure equality: no reserve for the empty theory. -/
theorem pure_equality_no_reserve :
    ¬ ∃ Φ : (Option Nat → Prop) → Nat,
      Corrected.IsTelescoping ShrinkP (fun _ _ => 1) Φ :=
  no_reserve some (fun _ _ h => Option.some.inj h)

end InfiniteCompletions

/-! ## §7 Free adjunction: if the system adds atoms itself, no reserve

State = (n atoms, survivors numbered below 2^n). Each round is: adjoin a fresh
atom (conservative, free, doubles the survivors), then commit to it (cost 1).
The round can repeat forever. Contrast §5: if atoms are granted by the
environment rather than taken by the system, each vocabulary has a finite
reserve and every grant buys exactly one more bit. -/

namespace FreeVocab
open FiniteCompletions

abbrev State := Nat × (Nat → Bool)

/-- Commit (same atoms, consistent strict shrink) or adjoin a fresh atom. -/
def Rev (s t : State) : Prop :=
  (t.1 = s.1 ∧ Shrink (2 ^ s.1) s.2 t.2) ∨
  (t.1 = s.1 + 1 ∧ t.2 = fun v => s.2 (v % 2 ^ s.1))

/-- Commitments cost 1; adjoining is conservative and free. -/
def cost (s t : State) : Nat := if t.1 = s.1 + 1 then 0 else 1

/-- Every atom so far decided false: one survivor, valuation 0. -/
def Z : Nat → Bool := fun v => decide (v = 0)

/-- Z after adjoining an atom to a vocabulary of k atoms: two survivors. -/
def A (k : Nat) : Nat → Bool := fun v => Z (v % 2 ^ k)

theorem adjoin_step (k : Nat) : Rev (k, Z) (k + 1, A k) := Or.inr ⟨rfl, rfl⟩

theorem commit_step (k : Nat) : Rev (k + 1, A k) (k + 1, Z) := by
  refine Or.inl ⟨rfl, ?_⟩
  show Shrink (2 ^ (k + 1)) (A k) Z
  have hp := Nat.two_pow_pos k
  have e : 2 ^ (k + 1) = 2 ^ k * 2 := Nat.pow_succ 2 k
  refine ⟨?_, ?_, ?_⟩
  · intro v _ hv
    have hv0 : v = 0 := by simpa [Z] using hv
    subst hv0
    simp [A, Z]
  · refine ⟨2 ^ k, by omega, ?_, ?_⟩
    · simp [A, Z, Nat.mod_self]
    · simp [Z] <;> omega
  · exact ⟨0, by omega, by simp [Z]⟩

theorem free_adjunction_no_reserve :
    ¬ ∃ Φ : State → Nat, Corrected.IsTelescoping Rev cost Φ := by
  intro ⟨Φ, hΦ⟩
  have key : ∀ k, Φ (k, Z) + k ≤ Φ (0, Z) := by
    intro k
    induction k with
    | zero => omega
    | succ k ih =>
      have h1 := hΦ (k, Z) (k + 1, A k) (adjoin_step k)
      have h2 := hΦ (k + 1, A k) (k + 1, Z) (commit_step k)
      have c1 : cost (k, Z) (k + 1, A k) = 0 := by simp [cost]
      have c2 : cost (k + 1, A k) (k + 1, Z) = 1 := by simp [cost]
      omega
  have := key (Φ (0, Z) + 1)
  omega

/-- Pricing adjunction does not help: under ANY cost function in which these
    commitments cost ≥ 1, however much adjoining costs, there is still no reserve. -/
theorem priced_adjunction_no_reserve (cst : State → State → Nat)
    (hcommit : ∀ k, 1 ≤ cst (k + 1, A k) (k + 1, Z)) :
    ¬ ∃ Φ : State → Nat, Corrected.IsTelescoping Rev cst Φ := by
  intro ⟨Φ, hΦ⟩
  have key : ∀ k, Φ (k, Z) + k ≤ Φ (0, Z) := by
    intro k
    induction k with
    | zero => omega
    | succ k ih =>
      have h1 := hΦ (k, Z) (k + 1, A k) (adjoin_step k)
      have h2 := hΦ (k + 1, A k) (k + 1, Z) (commit_step k)
      have c2 := hcommit k
      omega
  have := key (Φ (0, Z) + 1)
  omega

end FreeVocab

/-! ## §8 Retraction with a state-tracked allowance

State (S, k): theory S (surviving completions) and k retractions left.
· commit  (S, k)   → (S', k) : a base commitment, paid as before;
· retract (S, k+1) → (S', k) : spend one unit of allowance.

Retraction RESTORES reserve (it adds completions back), and the restored reserve
can be spent again. So the allowance weight K must cover the retraction's own
cost plus the reserve it gives back, not the re-validation cost alone. If the
ledger guarantees that one retraction restores at most b bits of reserve (e.g.
it may only undo the latest commitment), the generic theorem gives K = b + c
instead of n + c. -/

namespace Allowance
open FiniteCompletions

section Generic
variable {σ : Type}

/-- Commit at fixed allowance, or retract while spending one unit. -/
def Step (Rc Rr : σ → σ → Prop) (x y : σ × Nat) : Prop :=
  (Rc x.1 y.1 ∧ y.2 = x.2) ∨ (Rr x.1 y.1 ∧ x.2 = y.2 + 1)

/-- Commit steps keep k, retraction steps lower it, so the cost can tell them apart. -/
def cost (cc cr : σ → σ → Nat) (x y : σ × Nat) : Nat :=
  if y.2 = x.2 then cc x.1 y.1 else cr x.1 y.1

/-- §8a: if Ψ pays for commits, and every retraction's cost plus the reserve it
    restores is at most K, then Ψ(S) + K·k telescopes. -/
theorem two_component_telescopes (Rc Rr : σ → σ → Prop) (cc cr : σ → σ → Nat)
    (Ψ : σ → Nat) (K : Nat)
    (hΨ : Corrected.IsTelescoping Rc cc Ψ)
    (hK : ∀ s s', Rr s s' → cr s s' + Ψ s' ≤ Ψ s + K) :
    Corrected.IsTelescoping (Step Rc Rr) (cost cc cr) (fun x => Ψ x.1 + K * x.2) := by
  intro x y h
  show cost cc cr x y + (Ψ y.1 + K * y.2) ≤ Ψ x.1 + K * x.2
  rcases h with ⟨hc, hk⟩ | ⟨hr, hk⟩
  · have h1 := hΨ x.1 y.1 hc
    have e : cost cc cr x y = cc x.1 y.1 := by
      unfold cost
      split
      · rfl
      · contradiction
    rw [e, hk]
    omega
  · have h1 := hK x.1 y.1 hr
    have hne : y.2 ≠ x.2 := by omega
    have e : cost cc cr x y = cr x.1 y.1 := by
      unfold cost
      split
      · contradiction
      · rfl
    rw [e, hk, Nat.mul_add, Nat.mul_one]
    omega

end Generic

/-! ### §8b The propositional instance (bits, n atoms, re-validation cost c) -/

/-- Retraction (contraction): strictly enlarge the surviving completions. -/
def Grow (N : Nat) (S S' : Nat → Bool) : Prop :=
  (∀ v, v < N → S v = true → S' v = true) ∧ (∃ v, v < N ∧ S' v = true ∧ S v = false)

abbrev PState := (Nat → Bool) × Nat

def RStep (n : Nat) : PState → PState → Prop := Step (Shrink (2 ^ n)) (Grow (2 ^ n))
def RCost (n c : Nat) : PState → PState → Nat := cost (bitCost (2 ^ n)) (fun _ _ => c)
def RΦ (n c : Nat) : PState → Nat := fun x => bits (2 ^ n) x.1 + (n + c) * x.2

theorem bits_le_n (n : Nat) (S : Nat → Bool) : bits (2 ^ n) S ≤ n := by
  unfold bits
  by_cases h0 : count S (2 ^ n) = 0
  · rw [h0, Nat.log2_zero]; exact Nat.zero_le n
  · have hc := count_le S (2 ^ n)
    have hlt : count S (2 ^ n) < 2 ^ (n + 1) := by
      have e : 2 ^ (n + 1) = 2 ^ n * 2 := Nat.pow_succ 2 n
      have := Nat.two_pow_pos n
      omega
    have := (Nat.log2_lt h0).2 hlt
    omega

/-- K = n + c: re-validation cost plus the most reserve one retraction can restore. -/
theorem retraction_telescopes (n c : Nat) :
    Corrected.IsTelescoping (RStep n) (RCost n c) (RΦ n c) :=
  two_component_telescopes _ _ _ _ _ _ (bits_telescope (2 ^ n))
    (fun S S' _ => by
      have := bits_le_n n S'
      show c + bits (2 ^ n) S' ≤ bits (2 ^ n) S + (n + c)
      omega)

/-- Debt along any chain from (S, k) is at most n + k(n + c). -/
theorem retraction_debt_le (n c : Nat) (s : PState) (rest : List PState)
    (h : IsChainFrom (RStep n) s rest) :
    chainCost (RCost n c) s rest ≤ n + (n + c) * s.2 := by
  have h1 := Corrected.spent_plus_left_le _ _ _ (retraction_telescopes n c) rest s h
  have h2 := bits_le_n n s.1
  simp only [RΦ] at h1
  omega

/-! Tightness: from all completions, commit straight to one survivor (n bits),
    retract back (cost c), repeat once per unit of allowance. -/

def full : Nat → Bool := fun _ => true

theorem count_full : ∀ k, count full k = k := by
  intro k
  induction k with
  | zero => rfl
  | succ k ih => rw [count_succ_true full k rfl, ih]

theorem count_Z_succ : ∀ k, count FreeVocab.Z (k + 1) = 1 := by
  intro k
  induction k with
  | zero => rfl
  | succ k ih =>
    rw [count_succ_false FreeVocab.Z (k + 1) (by simp [FreeVocab.Z]), ih]

theorem count_Z_pow (n : Nat) : count FreeVocab.Z (2 ^ n) = 1 := by
  have e : 2 ^ n = (2 ^ n - 1) + 1 := by have := Nat.two_pow_pos n; omega
  rw [e]
  exact count_Z_succ _

theorem two_le_pow (n : Nat) (hn : 1 ≤ n) : 2 ≤ 2 ^ n := by
  cases n with
  | zero => omega
  | succ m =>
    have e : 2 ^ (m + 1) = 2 ^ m * 2 := Nat.pow_succ 2 m
    have := Nat.two_pow_pos m
    omega

theorem bits_full (n : Nat) : bits (2 ^ n) full = n := by
  unfold bits; rw [count_full, Nat.log2_two_pow]

theorem bitCost_full_Z (n : Nat) : bitCost (2 ^ n) full FreeVocab.Z = n := by
  unfold bitCost; rw [count_full, count_Z_pow, Nat.div_one, Nat.log2_two_pow]

theorem commit_full_Z (n : Nat) (hn : 1 ≤ n) : Shrink (2 ^ n) full FreeVocab.Z := by
  have h2 := two_le_pow n hn
  refine ⟨fun _ _ _ => rfl, ⟨1, by omega, rfl, by simp [FreeVocab.Z]⟩, ⟨0, by omega, by simp [FreeVocab.Z]⟩⟩

theorem retract_Z_full (n : Nat) (hn : 1 ≤ n) : Grow (2 ^ n) FreeVocab.Z full := by
  have h2 := two_le_pow n hn
  exact ⟨fun _ _ _ => rfl, ⟨1, by omega, rfl, by simp [FreeVocab.Z]⟩⟩

/-- §8b tightness: ANY reserve for this system is ≥ n + k(n + c) at
    (all completions, k). So RΦ is the least reserve there, and one unit of
    allowance is worth exactly n + c bits of debt. -/
theorem retraction_tight (n c : Nat) (hn : 1 ≤ n) (Φ : PState → Nat)
    (hΦ : Corrected.IsTelescoping (RStep n) (RCost n c) Φ) :
    ∀ k, n + k * (n + c) ≤ Φ (full, k) := by
  have hcommit : ∀ k, RStep n (full, k) (FreeVocab.Z, k) :=
    fun k => Or.inl ⟨commit_full_Z n hn, rfl⟩
  have hretract : ∀ k, RStep n (FreeVocab.Z, k + 1) (full, k) :=
    fun k => Or.inr ⟨retract_Z_full n hn, rfl⟩
  have ccommit : ∀ k, RCost n c (full, k) (FreeVocab.Z, k) = n := by
    intro k
    show (if k = k then bitCost (2 ^ n) full FreeVocab.Z else c) = n
    split
    · exact bitCost_full_Z n
    · omega
  have cretract : ∀ k, RCost n c (FreeVocab.Z, k + 1) (full, k) = c := by
    intro k
    show (if k = k + 1 then bitCost (2 ^ n) FreeVocab.Z full else c) = c
    split
    · omega
    · rfl
  intro k
  induction k with
  | zero =>
    have h1 := hΦ _ _ (hcommit 0)
    rw [ccommit 0] at h1
    omega
  | succ k ih =>
    have h1 := hΦ _ _ (hcommit (k + 1))
    have h2 := hΦ _ _ (hretract k)
    rw [ccommit (k + 1)] at h1
    rw [cretract k] at h2
    rw [Nat.succ_mul]
    omega

/-- Hence K must be at least n + c… -/
theorem allowance_weight_tight (n c K : Nat) (hn : 1 ≤ n)
    (hΦ : Corrected.IsTelescoping (RStep n) (RCost n c)
      (fun x => bits (2 ^ n) x.1 + K * x.2)) :
    n + c ≤ K := by
  have h := retraction_tight n c hn _ hΦ 1
  simp only [bits_full] at h
  omega

/-- …and in particular the re-validation cost alone (K = c) is not enough. -/
theorem revalidation_cost_alone_fails (n c : Nat) (hn : 1 ≤ n) :
    ¬ Corrected.IsTelescoping (RStep n) (RCost n c)
      (fun x => bits (2 ^ n) x.1 + c * x.2) := by
  intro h
  have := allowance_weight_tight n c c hn h
  omega

/-! ### §8c No allowance: pricing retraction cannot restore a reserve -/

/-- Retraction admissible with no allowance in the state, under ANY cost
    function: commit then retract is a cycle containing a costly commitment. -/
theorem unlimited_retraction_no_reserve (n : Nat) (hn : 1 ≤ n)
    (cst : (Nat → Bool) → (Nat → Bool) → Nat) (hpos : 1 ≤ cst full FreeVocab.Z) :
    ¬ ∃ Φ, Corrected.IsTelescoping
      (fun S S' => Shrink (2 ^ n) S S' ∨ Grow (2 ^ n) S S') cst Φ :=
  Corrected.costly_cycle_kills_potential _ cst full [FreeVocab.Z, full]
    ⟨Or.inl (commit_full_Z n hn), Or.inr (retract_Z_full n hn), trivial⟩
    rfl
    (by show 0 < cst full FreeVocab.Z + (cst FreeVocab.Z full + 0); omega)

/-! ### §8d Self-minting allowance: same verdict -/

/-- The system may also raise its own allowance. -/
def MintStep (n : Nat) (x y : PState) : Prop :=
  RStep n x y ∨ (y.1 = x.1 ∧ y.2 = x.2 + 1)

/-- Under ANY cost function (minting may be priced as high as you like):
    commit, retract, mint is a cycle containing a costly commitment. -/
theorem minting_no_reserve (n : Nat) (hn : 1 ≤ n) (cst : PState → PState → Nat)
    (hpos : 1 ≤ cst (full, 1) (FreeVocab.Z, 1)) :
    ¬ ∃ Φ, Corrected.IsTelescoping (MintStep n) cst Φ :=
  Corrected.costly_cycle_kills_potential _ cst (full, 1)
    [(FreeVocab.Z, 1), (full, 0), (full, 1)]
    ⟨Or.inl (Or.inl ⟨commit_full_Z n hn, rfl⟩),
     Or.inl (Or.inr ⟨retract_Z_full n hn, rfl⟩),
     Or.inr ⟨rfl, rfl⟩, trivial⟩
    rfl
    (by
      show 0 < cst (full, 1) (FreeVocab.Z, 1) +
        (cst (FreeVocab.Z, 1) (full, 0) + (cst (full, 0) (full, 1) + 0))
      omega)

end Allowance

/-! ## §9 Refinement: a concrete append-only ledger

The ledger: commit / retract over 2^n valuations; an append-only log whose
entries carry a provenance tag and the debt they recorded; a retraction
allowance; recorded debt; and a cumulative provenance tag. A guard accepts a
step only if the recorded cost is paid by the drop in §8's reserve RΦ.
`refine` maps a ledger state onto §8's model, and the two refinement
obligations (step simulation, debt domination) carry the debt bound over.

Accounting is exact: a commit records the reserve it actually uses (the drop
in undecided bits), so on commit-only runs spent + left = start holds with
equality. This drop can exceed §8's whole-bit cost (4 → 3 survivors: drop 1,
whole bits 0), so the refinement targets §8's model re-priced with the drop
(§9.0), not the original bitCost model.

Provenance tags live in a join-semilattice (the ax × emp product included):
cumProv never decreases, equals the join of every logged tag, and dominates
each of them. -/

/-! ### §9.0 Exact reserve-drop accounting, at the model level -/

namespace FiniteCompletions

theorem log2_mono {m m' : Nat} (h : m' ≤ m) : Nat.log2 m' ≤ Nat.log2 m := by
  by_cases h0 : m' = 0
  · rw [h0, Nat.log2_zero]; exact Nat.zero_le _
  · by_cases hc : Nat.log2 m < Nat.log2 m'
    · have e1 := (Nat.log2_lt (n := m) (by omega)).1 hc
      have e2 := Nat.log2_self_le (n := m') h0
      omega
    · omega

/-- Reserve a commitment actually uses: the drop in undecided bits. -/
def dropCost (N : Nat) (S S' : Nat → Bool) : Nat := bits N S - bits N S'

theorem bits_mono_shrink (N : Nat) (S S' : Nat → Bool) (h : Shrink N S S') :
    bits N S' ≤ bits N S := by
  obtain ⟨hsub, hdrop, _⟩ := h
  have := count_strict S S' N hsub hdrop
  exact log2_mono (by omega)

/-- Exact: what a commitment records plus what is left is what there was. -/
theorem drop_exact (N : Nat) (S S' : Nat → Bool) (h : Shrink N S S') :
    dropCost N S S' + bits N S' = bits N S := by
  have := bits_mono_shrink N S S' h
  unfold dropCost
  omega

theorem drop_telescopes (N : Nat) :
    Corrected.IsTelescoping (Shrink N) (dropCost N) (bits N) :=
  fun S S' h => Nat.le_of_eq (drop_exact N S S' h)

/-- The patch only removes under-recording: the drop is never less than the
    whole bits decided. -/
theorem bitCost_le_drop (N : Nat) (S S' : Nat → Bool) (h : Shrink N S S') :
    bitCost N S S' ≤ dropCost N S S' := by
  obtain ⟨hsub, hdrop, hne⟩ := h
  have h1 := count_strict S S' N hsub hdrop
  have h2 := count_pos S' N hne
  have := log2_div_add (count S N) (count S' N) h2 (by omega)
  unfold bitCost dropCost bits
  omega

end FiniteCompletions

namespace Allowance
open FiniteCompletions

/-- §8's model, re-priced: a commit costs its reserve drop. -/
def RCostX (n c : Nat) : PState → PState → Nat := cost (dropCost (2 ^ n)) (fun _ _ => c)

theorem retraction_telescopes_exact (n c : Nat) :
    Corrected.IsTelescoping (RStep n) (RCostX n c) (RΦ n c) :=
  two_component_telescopes _ _ _ _ _ _ (drop_telescopes (2 ^ n))
    (fun S S' _ => by
      have := bits_le_n n S'
      show c + bits (2 ^ n) S' ≤ bits (2 ^ n) S + (n + c)
      omega)

theorem retraction_debt_le_exact (n c : Nat) (s : PState) (rest : List PState)
    (h : IsChainFrom (RStep n) s rest) :
    chainCost (RCostX n c) s rest ≤ n + (n + c) * s.2 := by
  have h1 := Corrected.spent_plus_left_le _ _ _ (retraction_telescopes_exact n c) rest s h
  have h2 := bits_le_n n s.1
  simp only [RΦ] at h1
  omega

end Allowance

namespace Ledger
open FiniteCompletions Allowance

/-! ### §9a Provenance tags: a join-semilattice -/

/-- A join-semilattice with bottom, spelled out (core Lean has no lattice
    classes). -/
class JoinSemilattice (P : Type) where
  bot : P
  join : P → P → P
  le : P → P → Prop
  le_refl : ∀ a, le a a
  le_trans : ∀ a b c, le a b → le b c → le a c
  le_join_left : ∀ a b, le a (join a b)
  le_join_right : ∀ a b, le b (join a b)
  join_le : ∀ a b c, le a c → le b c → le (join a b) c
  bot_le : ∀ a, le bot a

/-- Products are componentwise: this is the ax × emp tag. -/
instance (A B : Type) [JoinSemilattice A] [JoinSemilattice B] :
    JoinSemilattice (A × B) where
  bot := (JoinSemilattice.bot, JoinSemilattice.bot)
  join x y := (JoinSemilattice.join x.1 y.1, JoinSemilattice.join x.2 y.2)
  le x y := JoinSemilattice.le x.1 y.1 ∧ JoinSemilattice.le x.2 y.2
  le_refl x := ⟨JoinSemilattice.le_refl x.1, JoinSemilattice.le_refl x.2⟩
  le_trans _ _ _ h1 h2 :=
    ⟨JoinSemilattice.le_trans _ _ _ h1.1 h2.1, JoinSemilattice.le_trans _ _ _ h1.2 h2.2⟩
  le_join_left _ _ := ⟨JoinSemilattice.le_join_left _ _, JoinSemilattice.le_join_left _ _⟩
  le_join_right _ _ := ⟨JoinSemilattice.le_join_right _ _, JoinSemilattice.le_join_right _ _⟩
  join_le _ _ _ h1 h2 :=
    ⟨JoinSemilattice.join_le _ _ _ h1.1 h2.1, JoinSemilattice.join_le _ _ _ h1.2 h2.2⟩
  bot_le _ := ⟨JoinSemilattice.bot_le _, JoinSemilattice.bot_le _⟩

/-- Example component: levels ordered by ≤ and joined by max. -/
instance : JoinSemilattice Nat where
  bot := 0
  join := max
  le := (· ≤ ·)
  le_refl := Nat.le_refl
  le_trans _ _ _ := Nat.le_trans
  le_join_left := Nat.le_max_left
  le_join_right := Nat.le_max_right
  join_le _ _ _ h1 h2 := Nat.max_le.2 ⟨h1, h2⟩
  bot_le := Nat.zero_le

/-! ### §9b The ledger -/

inductive OpKind where
  | commit
  | retract

/-- One log entry: the operation, its provenance tag, the debt it recorded. -/
structure Entry (P : Type) where
  op : OpKind
  prov : P
  cost : Nat

/-- Ledger over n atoms with provenance tags of type P. -/
structure LedgerState (n : Nat) (P : Type) where
  log : List (Entry P)
  active : Nat → Bool
  allowance : Nat
  recordedDebt : Nat
  cumProv : P

inductive Op (P : Type) where
  | commit (mask : Nat → Bool) (prov : P)
  | retract (restored : Nat → Bool) (prov : P) (revalCost : Nat)

def Op.isCommit {P : Type} : Op P → Bool
  | .commit _ _ => true
  | .retract _ _ _ => false

variable {n : Nat} {P : Type} [JoinSemilattice P]

/-- The abstraction map onto §8's model. -/
def refine (L : LedgerState n P) : PState := (L.active, L.allowance)

def CommitPre (L : LedgerState n P) (mask : Nat → Bool) : Prop :=
  Shrink (2 ^ n) L.active (fun v => L.active v && mask v)

def RetractPre (c : Nat) (L : LedgerState n P) (restored : Nat → Bool) (r : Nat) : Prop :=
  1 ≤ L.allowance ∧ Grow (2 ^ n) L.active restored ∧ r ≤ c

/-- Patch 1: a commit records the reserve it actually uses. -/
def commitCost (L : LedgerState n P) (mask : Nat → Bool) : Nat :=
  dropCost (2 ^ n) L.active (fun v => L.active v && mask v)

def commitNext (L : LedgerState n P) (mask : Nat → Bool) (prov : P) : LedgerState n P where
  log := L.log ++ [⟨.commit, prov, commitCost L mask⟩]
  active := fun v => L.active v && mask v
  allowance := L.allowance
  recordedDebt := L.recordedDebt + commitCost L mask
  cumProv := JoinSemilattice.join L.cumProv prov

def retractNext (L : LedgerState n P) (restored : Nat → Bool) (prov : P) (r : Nat) :
    LedgerState n P where
  log := L.log ++ [⟨.retract, prov, r⟩]
  active := restored
  allowance := L.allowance - 1
  recordedDebt := L.recordedDebt + r
  cumProv := JoinSemilattice.join L.cumProv prov

/-- The guard: the recorded cost is paid by the drop in the reserve RΦ. -/
def GuardOK (c : Nat) (L L' : LedgerState n P) (cost : Nat) : Prop :=
  cost + RΦ n c (refine L') ≤ RΦ n c (refine L)

instance (N : Nat) (S S' : Nat → Bool) : Decidable (Shrink N S S') :=
  inferInstanceAs (Decidable ((∀ v, v < N → S' v = true → S v = true) ∧
    (∃ v, v < N ∧ S v = true ∧ S' v = false) ∧ (∃ v, v < N ∧ S' v = true)))

instance (N : Nat) (S S' : Nat → Bool) : Decidable (Grow N S S') :=
  inferInstanceAs (Decidable ((∀ v, v < N → S v = true → S' v = true) ∧
    (∃ v, v < N ∧ S' v = true ∧ S v = false)))

instance (L : LedgerState n P) (mask : Nat → Bool) : Decidable (CommitPre L mask) :=
  inferInstanceAs (Decidable (Shrink (2 ^ n) L.active (fun v => L.active v && mask v)))

instance (c : Nat) (L : LedgerState n P) (restored : Nat → Bool) (r : Nat) :
    Decidable (RetractPre c L restored r) :=
  inferInstanceAs (Decidable (1 ≤ L.allowance ∧ Grow (2 ^ n) L.active restored ∧ r ≤ c))

instance (c : Nat) (L L' : LedgerState n P) (cost : Nat) : Decidable (GuardOK c L L' cost) :=
  inferInstanceAs (Decidable (cost + RΦ n c (refine L') ≤ RΦ n c (refine L)))

/-- One guarded step: check the precondition, build the next state, accept it
    only if the guard holds. Returns the next state and the recorded cost. -/
def step (c : Nat) (L : LedgerState n P) : Op P → Option (LedgerState n P × Nat)
  | .commit mask prov =>
    if CommitPre L mask then
      if GuardOK c L (commitNext L mask prov) (commitCost L mask) then
        some (commitNext L mask prov, commitCost L mask)
      else none
    else none
  | .retract restored prov r =>
    if RetractPre c L restored r then
      if GuardOK c L (retractNext L restored prov r) r then
        some (retractNext L restored prov r, r)
      else none
    else none

/-! ### §9c What an accepted step guarantees -/

theorem step_commit_inv (c : Nat) (L L' : LedgerState n P) (cost : Nat)
    (mask : Nat → Bool) (prov : P) (h : step c L (.commit mask prov) = some (L', cost)) :
    CommitPre L mask ∧ GuardOK c L L' cost ∧ L' = commitNext L mask prov ∧
      cost = commitCost L mask := by
  by_cases hpre : CommitPre L mask
  · by_cases hg : GuardOK c L (commitNext L mask prov) (commitCost L mask)
    · simp [step, hpre, hg] at h
      obtain ⟨rfl, rfl⟩ := h
      exact ⟨hpre, hg, rfl, rfl⟩
    · simp [step, hpre, hg] at h
  · simp [step, hpre] at h

theorem step_retract_inv (c : Nat) (L L' : LedgerState n P) (cost : Nat)
    (restored : Nat → Bool) (prov : P) (r : Nat)
    (h : step c L (.retract restored prov r) = some (L', cost)) :
    RetractPre c L restored r ∧ GuardOK c L L' cost ∧ L' = retractNext L restored prov r ∧
      cost = r := by
  by_cases hpre : RetractPre c L restored r
  · by_cases hg : GuardOK c L (retractNext L restored prov r) r
    · simp [step, hpre, hg] at h
      obtain ⟨rfl, rfl⟩ := h
      exact ⟨hpre, hg, rfl, rfl⟩
    · simp [step, hpre, hg] at h
  · simp [step, hpre] at h

/-- One theorem used by everything below: an accepted step is an RStep of the
    model (simulation); its recorded cost is ≤ RCostX, equal for commits
    (domination); it passed the guard; recorded debt grew by exactly its cost;
    the log grew by exactly one entry; and cumProv absorbed that entry's tag. -/
theorem step_accepted (c : Nat) (L L' : LedgerState n P) (cost : Nat) (op : Op P)
    (h : step c L op = some (L', cost)) :
    (RStep n (refine L) (refine L') ∧ cost ≤ RCostX n c (refine L) (refine L')) ∧
    (GuardOK c L L' cost ∧ L'.recordedDebt = L.recordedDebt + cost) ∧
    (∃ e : Entry P, L'.log = L.log ++ [e] ∧ e.cost = cost ∧
      L'.cumProv = JoinSemilattice.join L.cumProv e.prov) := by
  cases op with
  | commit mask prov =>
    obtain ⟨hpre, hg, rfl, rfl⟩ := step_commit_inv c L L' cost mask prov h
    refine ⟨⟨Or.inl ⟨hpre, rfl⟩, ?_⟩, ⟨hg, rfl⟩,
      ⟨.commit, prov, commitCost L mask⟩, rfl, rfl, rfl⟩
    show commitCost L mask ≤ (if L.allowance = L.allowance then
      dropCost (2 ^ n) L.active (fun v => L.active v && mask v) else c)
    split
    · exact Nat.le_refl _
    · omega
  | retract restored prov r =>
    obtain ⟨hpre, hg, rfl, hc⟩ := step_retract_inv c L L' cost restored prov r h
    obtain ⟨hk, hgrow, hr⟩ := hpre
    refine ⟨⟨Or.inr ⟨hgrow, ?_⟩, ?_⟩, ⟨hg, ?_⟩, ⟨.retract, prov, r⟩, rfl, hc.symm, rfl⟩
    · show L.allowance = (L.allowance - 1) + 1
      omega
    · show cost ≤ (if L.allowance - 1 = L.allowance then
        dropCost (2 ^ n) L.active restored else c)
      split
      · omega
      · omega
    · show L.recordedDebt + r = L.recordedDebt + cost
      omega

/-- Patch 1, per step: an accepted commit records exactly the reserve it uses. -/
theorem commit_exact (c : Nat) (L L' : LedgerState n P) (cost : Nat) (mask : Nat → Bool)
    (prov : P) (h : step c L (.commit mask prov) = some (L', cost)) :
    L'.recordedDebt + bits (2 ^ n) L'.active = L.recordedDebt + bits (2 ^ n) L.active := by
  obtain ⟨hpre, _, rfl, rfl⟩ := step_commit_inv c L L' cost mask prov h
  have := drop_exact (2 ^ n) L.active (fun v => L.active v && mask v) hpre
  show L.recordedDebt + commitCost L mask + bits (2 ^ n) (fun v => L.active v && mask v) =
    L.recordedDebt + bits (2 ^ n) L.active
  unfold commitCost
  omega

/-! ### §9d Runs, and the transfer -/

section Runs
variable {O : Type}

/-- Process operations in order; a refused operation leaves the state as it was. -/
def runWith (f : LedgerState n P → O → Option (LedgerState n P × Nat)) :
    LedgerState n P → List O → LedgerState n P
  | L, [] => L
  | L, op :: ops =>
    match f L op with
    | some (L', _) => runWith f L' ops
    | none => runWith f L ops

/-- The model states visited by the accepted steps. -/
def traceWith (f : LedgerState n P → O → Option (LedgerState n P × Nat)) :
    LedgerState n P → List O → List PState
  | _, [] => []
  | L, op :: ops =>
    match f L op with
    | some (L', _) => refine L' :: traceWith f L' ops
    | none => traceWith f L ops

/-- The two refinement obligations, as a property of a step function. -/
def Refines (c : Nat) (f : LedgerState n P → O → Option (LedgerState n P × Nat)) : Prop :=
  ∀ L op L' cost, f L op = some (L', cost) →
    RStep n (refine L) (refine L') ∧ cost ≤ RCostX n c (refine L) (refine L') ∧
      L'.recordedDebt = L.recordedDebt + cost

omit [JoinSemilattice P] in
/-- Trace inclusion: the accepted steps of any run form a chain of the model. -/
theorem traceWith_chain (c : Nat) (f : LedgerState n P → O → Option (LedgerState n P × Nat))
    (hf : Refines c f) : ∀ (ops : List O) (L : LedgerState n P),
    IsChainFrom (RStep n) (refine L) (traceWith f L ops) := by
  intro ops
  induction ops with
  | nil => intro L; trivial
  | cons op ops ih =>
    intro L
    simp only [traceWith]
    cases h : f L op with
    | none => exact ih L
    | some p =>
      obtain ⟨L', cost⟩ := p
      exact ⟨(hf L op L' cost h).1, ih L'⟩

omit [JoinSemilattice P] in
theorem runWith_debt_le_trace (c : Nat)
    (f : LedgerState n P → O → Option (LedgerState n P × Nat))
    (hf : Refines c f) : ∀ (ops : List O) (L : LedgerState n P),
    (runWith f L ops).recordedDebt ≤
      L.recordedDebt + chainCost (RCostX n c) (refine L) (traceWith f L ops) := by
  intro ops
  induction ops with
  | nil => intro L; simp [runWith, traceWith, chainCost]
  | cons op ops ih =>
    intro L
    simp only [runWith, traceWith]
    cases h : f L op with
    | none => exact ih L
    | some p =>
      obtain ⟨L', cost⟩ := p
      obtain ⟨_, hdom, hdebt⟩ := hf L op L' cost h
      have hih := ih L'
      show (runWith f L' ops).recordedDebt ≤ L.recordedDebt +
        (RCostX n c (refine L) (refine L') +
          chainCost (RCostX n c) (refine L') (traceWith f L' ops))
      omega

omit [JoinSemilattice P] in
/-- The transfer: any ledger meeting the two obligations inherits the debt
    bound. From any starting state, over any sequence of operations, recorded
    debt grows by at most n + (n + c)·k₀. -/
theorem refinement_transfer (c : Nat)
    (f : LedgerState n P → O → Option (LedgerState n P × Nat))
    (hf : Refines c f) (L : LedgerState n P) (ops : List O) :
    (runWith f L ops).recordedDebt ≤ L.recordedDebt + (n + (n + c) * L.allowance) := by
  have h1 := runWith_debt_le_trace c f hf ops L
  have h2 := retraction_debt_le_exact n c (refine L) (traceWith f L ops)
    (traceWith_chain c f hf ops L)
  have e : (refine L).2 = L.allowance := rfl
  rw [e] at h2
  omega

end Runs

/-- The concrete ledger. -/
def run (c : Nat) : LedgerState n P → List (Op P) → LedgerState n P := runWith (step c)

theorem step_refines (c : Nat) : Refines c (step (n := n) (P := P) c) := by
  intro L op L' cost h
  obtain ⟨⟨hs, hd⟩, ⟨_, he⟩, _⟩ := step_accepted c L L' cost op h
  exact ⟨hs, hd, he⟩

theorem run_debt_le (c : Nat) (L : LedgerState n P) (ops : List (Op P)) :
    (run c L ops).recordedDebt ≤ L.recordedDebt + (n + (n + c) * L.allowance) :=
  refinement_transfer c (step c) (step_refines c) L ops

/-- From an empty ledger with allowance k₀: recorded debt ≤ n + (n + c)·k₀. -/
theorem run_debt_le_from_empty (c k₀ : Nat) (S : Nat → Bool) (ops : List (Op P)) :
    (run c (⟨[], S, k₀, 0, JoinSemilattice.bot⟩ : LedgerState n P) ops).recordedDebt ≤
      n + (n + c) * k₀ := by
  have := run_debt_le c (⟨[], S, k₀, 0, JoinSemilattice.bot⟩ : LedgerState n P) ops
  simpa using this

/-- Patch 1, per run: on commit-only runs the account is exact,
    spent + left = start. -/
theorem run_commit_only_exact (c : Nat) : ∀ (ops : List (Op P)) (L : LedgerState n P),
    (∀ op ∈ ops, op.isCommit = true) →
    (run c L ops).recordedDebt + bits (2 ^ n) (run c L ops).active =
      L.recordedDebt + bits (2 ^ n) L.active := by
  intro ops
  induction ops with
  | nil => intro L _; simp [run, runWith]
  | cons op ops ih =>
    intro L hall
    have hops : ∀ o ∈ ops, o.isCommit = true := fun o ho => hall o (by simp [ho])
    have hop : op.isCommit = true := hall op (by simp)
    cases op with
    | retract restored prov r => simp [Op.isCommit] at hop
    | commit mask prov =>
      simp only [run, runWith]
      cases h : step c L (.commit mask prov) with
      | none => exact ih L hops
      | some p =>
        obtain ⟨L', cost⟩ := p
        have he := commit_exact c L L' cost mask prov h
        have hih := ih L' hops
        show (run c L' ops).recordedDebt + bits (2 ^ n) (run c L' ops).active =
          L.recordedDebt + bits (2 ^ n) L.active
        omega

/-! ### §9e The guard -/

/-- Given its precondition, a commit always passes the guard. -/
theorem guard_commit_ok (c : Nat) (L : LedgerState n P) (mask : Nat → Bool) (prov : P)
    (hpre : CommitPre L mask) :
    GuardOK c L (commitNext L mask prov) (commitCost L mask) := by
  have hstep : RStep n (refine L) (refine (commitNext L mask prov)) := Or.inl ⟨hpre, rfl⟩
  have ht := retraction_telescopes_exact n c _ _ hstep
  have hc : RCostX n c (refine L) (refine (commitNext L mask prov)) = commitCost L mask := by
    show (if L.allowance = L.allowance then
      dropCost (2 ^ n) L.active (fun v => L.active v && mask v) else c) = commitCost L mask
    split
    · rfl
    · omega
  rw [hc] at ht
  exact ht

/-- Given its precondition, a retraction always passes the guard. -/
theorem guard_retract_ok (c : Nat) (L : LedgerState n P) (restored : Nat → Bool)
    (prov : P) (r : Nat) (hpre : RetractPre c L restored r) :
    GuardOK c L (retractNext L restored prov r) r := by
  obtain ⟨hk, hgrow, hr⟩ := hpre
  have hstep : RStep n (refine L) (refine (retractNext L restored prov r)) :=
    Or.inr ⟨hgrow, by show L.allowance = (L.allowance - 1) + 1; omega⟩
  have ht := retraction_telescopes_exact n c _ _ hstep
  have hc : RCostX n c (refine L) (refine (retractNext L restored prov r)) = c := by
    show (if L.allowance - 1 = L.allowance then dropCost (2 ^ n) L.active restored else c) = c
    split
    · omega
    · rfl
  rw [hc] at ht
  show r + RΦ n c (refine (retractNext L restored prov r)) ≤ RΦ n c (refine L)
  omega

/-- So the guard never blocks a valid operation. The preconditions are what
    restrict the ledger; the guard is a second, independent check. -/
theorem commit_accepted (c : Nat) (L : LedgerState n P) (mask : Nat → Bool) (prov : P)
    (hpre : CommitPre L mask) :
    step c L (.commit mask prov) = some (commitNext L mask prov, commitCost L mask) := by
  simp [step, hpre, guard_commit_ok c L mask prov hpre]

theorem retract_accepted (c : Nat) (L : LedgerState n P) (restored : Nat → Bool)
    (prov : P) (r : Nat) (hpre : RetractPre c L restored r) :
    step c L (.retract restored prov r) = some (retractNext L restored prov r, r) := by
  simp [step, hpre, guard_retract_ok c L restored prov r hpre]

omit [JoinSemilattice P] in
/-- The guard alone is enough. For ANY step function (any operation type, any
    preconditions or none) whose accepted transitions pass the guard and record
    their cost, recorded debt plus reserve never exceeds its starting value. -/
theorem guard_alone_suffices {O : Type} (c : Nat)
    (f : LedgerState n P → O → Option (LedgerState n P × Nat))
    (hf : ∀ L op L' cost, f L op = some (L', cost) →
      GuardOK c L L' cost ∧ L'.recordedDebt = L.recordedDebt + cost) :
    ∀ (ops : List O) (L : LedgerState n P),
      (runWith f L ops).recordedDebt + RΦ n c (refine (runWith f L ops)) ≤
        L.recordedDebt + RΦ n c (refine L) := by
  intro ops
  induction ops with
  | nil => intro L; simp [runWith]
  | cons op ops ih =>
    intro L
    simp only [runWith]
    cases h : f L op with
    | none => exact ih L
    | some p =>
      obtain ⟨L', cost⟩ := p
      obtain ⟨hg, hd⟩ := hf L op L' cost h
      have hih := ih L'
      unfold GuardOK at hg
      show (runWith f L' ops).recordedDebt + RΦ n c (refine (runWith f L' ops)) ≤
        L.recordedDebt + RΦ n c (refine L)
      omega

omit [JoinSemilattice P] in
theorem guard_alone_bound {O : Type} (c : Nat)
    (f : LedgerState n P → O → Option (LedgerState n P × Nat))
    (hf : ∀ L op L' cost, f L op = some (L', cost) →
      GuardOK c L L' cost ∧ L'.recordedDebt = L.recordedDebt + cost)
    (L : LedgerState n P) (ops : List O) :
    (runWith f L ops).recordedDebt ≤ L.recordedDebt + (n + (n + c) * L.allowance) := by
  have h1 := guard_alone_suffices c f hf ops L
  have h2 := bits_le_n n L.active
  have e : RΦ n c (refine L) = bits (2 ^ n) L.active + (n + c) * L.allowance := rfl
  rw [e] at h1
  omega

omit [JoinSemilattice P] in
/-- Pure minting (allowance up, theory unchanged) is refused once n + c ≥ 1. -/
theorem guard_refuses_mint (c : Nat) (hnc : 1 ≤ n + c) (L L' : LedgerState n P)
    (cost : Nat) (hS : L'.active = L.active) (hk : L'.allowance = L.allowance + 1) :
    ¬ GuardOK c L L' cost := by
  intro hg
  have e1 : RΦ n c (refine L') = bits (2 ^ n) L.active + (n + c) * (L.allowance + 1) := by
    show bits (2 ^ n) L'.active + (n + c) * L'.allowance = _
    rw [hS, hk]
  have e2 : RΦ n c (refine L) = bits (2 ^ n) L.active + (n + c) * L.allowance := rfl
  have e3 : (n + c) * (L.allowance + 1) = (n + c) * L.allowance + (n + c) := by
    rw [Nat.mul_add, Nat.mul_one]
  unfold GuardOK at hg
  rw [e1, e2] at hg
  omega

omit [JoinSemilattice P] in
/-- Patch 3: when c ≥ 1 the guard refuses ANY transition that raises the
    allowance, whatever happens to the theory and whatever cost is recorded. -/
theorem guard_refuses_allowance_increase (c : Nat) (hc : 1 ≤ c) (L L' : LedgerState n P)
    (cost : Nat) (hk : L.allowance + 1 ≤ L'.allowance) : ¬ GuardOK c L L' cost := by
  intro hg
  have hb := bits_le_n n L.active
  have hmul : (n + c) * (L.allowance + 1) ≤ (n + c) * L'.allowance :=
    Nat.mul_le_mul_left _ hk
  have e3 : (n + c) * (L.allowance + 1) = (n + c) * L.allowance + (n + c) := by
    rw [Nat.mul_add, Nat.mul_one]
  have e1 : RΦ n c (refine L') = bits (2 ^ n) L'.active + (n + c) * L'.allowance := rfl
  have e2 : RΦ n c (refine L) = bits (2 ^ n) L.active + (n + c) * L.allowance := rfl
  unfold GuardOK at hg
  rw [e1, e2] at hg
  omega

omit [JoinSemilattice P] in
/-- …and c ≥ 1 cannot be dropped: with c = 0, giving up the entire reserve for
    one unit of allowance (an even trade at rate n + c = n) passes the guard. -/
theorem c_zero_conversion_passes (L L' : LedgerState n P)
    (hS : L.active = full) (hS' : L'.active = FreeVocab.Z)
    (hk : L'.allowance = L.allowance + 1) : GuardOK 0 L L' 0 := by
  have h1 : bits (2 ^ n) L.active = n := by rw [hS]; exact bits_full n
  have h2 : bits (2 ^ n) L'.active = 0 := by
    rw [hS']
    show Nat.log2 (count FreeVocab.Z (2 ^ n)) = 0
    rw [count_Z_pow]
    exact Nat.log2_two_pow (n := 0)
  have e3 : (n + 0) * (L.allowance + 1) = (n + 0) * L.allowance + (n + 0) := by
    rw [Nat.mul_add, Nat.mul_one]
  show 0 + (bits (2 ^ n) L'.active + (n + 0) * L'.allowance) ≤
    bits (2 ^ n) L.active + (n + 0) * L.allowance
  rw [hk]
  omega

/-! ### §9f Append-only log, recorded debt, and provenance -/

def logDebt : List (Entry P) → Nat
  | [] => 0
  | e :: es => e.cost + logDebt es

omit [JoinSemilattice P] in
theorem logDebt_append (xs ys : List (Entry P)) :
    logDebt (xs ++ ys) = logDebt xs + logDebt ys := by
  induction xs with
  | nil => simp [logDebt]
  | cons x xs ih =>
    show x.cost + logDebt (xs ++ ys) = x.cost + logDebt xs + logDebt ys
    rw [ih]
    omega

/-- No entry, and so no provenance tag, is ever erased or changed. -/
theorem run_append_only (c : Nat) : ∀ (ops : List (Op P)) (L : LedgerState n P),
    ∃ suffix, (run c L ops).log = L.log ++ suffix := by
  intro ops
  induction ops with
  | nil => intro L; exact ⟨[], by simp [run, runWith]⟩
  | cons op ops ih =>
    intro L
    simp only [run, runWith]
    cases h : step c L op with
    | none => exact ih L
    | some p =>
      obtain ⟨L', cost⟩ := p
      obtain ⟨_, _, e, he, _⟩ := step_accepted c L L' cost op h
      obtain ⟨s, hs⟩ := ih L'
      refine ⟨e :: s, ?_⟩
      show (run c L' ops).log = L.log ++ e :: s
      simp [hs, he]

/-- Recorded debt always equals the sum of the costs in the log. -/
theorem run_debt_eq_log (c : Nat) : ∀ (ops : List (Op P)) (L : LedgerState n P),
    L.recordedDebt = logDebt L.log →
      (run c L ops).recordedDebt = logDebt (run c L ops).log := by
  intro ops
  induction ops with
  | nil => intro L hL; simpa [run, runWith] using hL
  | cons op ops ih =>
    intro L hL
    simp only [run, runWith]
    cases h : step c L op with
    | none => exact ih L hL
    | some p =>
      obtain ⟨L', cost⟩ := p
      obtain ⟨_, ⟨_, hd⟩, e, he, hc, _⟩ := step_accepted c L L' cost op h
      apply ih L'
      rw [hd, he, logDebt_append, hL]
      simp [logDebt, hc]

/-- Cumulative provenance of a log: the join of every entry's tag, in order. -/
def logJoin (log : List (Entry P)) : P :=
  log.foldl (fun acc e => JoinSemilattice.join acc e.prov) JoinSemilattice.bot

theorem foldl_join_ge_init : ∀ (log : List (Entry P)) (init : P),
    JoinSemilattice.le init
      (log.foldl (fun acc e => JoinSemilattice.join acc e.prov) init) := by
  intro log
  induction log with
  | nil => intro init; exact JoinSemilattice.le_refl init
  | cons x xs ih =>
    intro init
    exact JoinSemilattice.le_trans _ _ _ (JoinSemilattice.le_join_left init x.prov)
      (ih (JoinSemilattice.join init x.prov))

theorem foldl_join_ge_mem : ∀ (log : List (Entry P)) (init : P) (e : Entry P), e ∈ log →
    JoinSemilattice.le e.prov
      (log.foldl (fun acc e => JoinSemilattice.join acc e.prov) init) := by
  intro log
  induction log with
  | nil => intro init e he; cases he
  | cons x xs ih =>
    intro init e he
    rcases List.mem_cons.1 he with heq | hmem
    · rw [heq]
      exact JoinSemilattice.le_trans _ _ _ (JoinSemilattice.le_join_right init x.prov)
        (foldl_join_ge_init xs (JoinSemilattice.join init x.prov))
    · exact ih (JoinSemilattice.join init x.prov) e hmem

/-- Patch 2a: cumProv never decreases along a run. -/
theorem run_cumProv_mono (c : Nat) : ∀ (ops : List (Op P)) (L : LedgerState n P),
    JoinSemilattice.le L.cumProv (run c L ops).cumProv := by
  intro ops
  induction ops with
  | nil => intro L; exact JoinSemilattice.le_refl _
  | cons op ops ih =>
    intro L
    simp only [run, runWith]
    cases h : step c L op with
    | none => exact ih L
    | some p =>
      obtain ⟨L', cost⟩ := p
      obtain ⟨_, _, e, _, _, hprov⟩ := step_accepted c L L' cost op h
      have h1 : JoinSemilattice.le L.cumProv L'.cumProv := by
        rw [hprov]; exact JoinSemilattice.le_join_left _ _
      exact JoinSemilattice.le_trans _ _ _ h1 (ih L')

/-- Patch 2b: cumProv is exactly the join of the tags in the log. -/
theorem run_cumProv_eq_logJoin (c : Nat) : ∀ (ops : List (Op P)) (L : LedgerState n P),
    L.cumProv = logJoin L.log → (run c L ops).cumProv = logJoin (run c L ops).log := by
  intro ops
  induction ops with
  | nil => intro L hL; simpa [run, runWith] using hL
  | cons op ops ih =>
    intro L hL
    simp only [run, runWith]
    cases h : step c L op with
    | none => exact ih L hL
    | some p =>
      obtain ⟨L', cost⟩ := p
      obtain ⟨_, _, e, he, _, hprov⟩ := step_accepted c L L' cost op h
      apply ih L'
      rw [hprov, he, hL]
      simp [logJoin, List.foldl_append]

/-- Patch 2c: every tag ever logged is below cumProv, so no provenance can be
    dropped from the summary. -/
theorem run_prov_dominates (c : Nat) (ops : List (Op P)) (L : LedgerState n P)
    (hL : L.cumProv = logJoin L.log) :
    ∀ e ∈ (run c L ops).log, JoinSemilattice.le e.prov (run c L ops).cumProv := by
  intro e he
  rw [run_cumProv_eq_logJoin c ops L hL]
  exact foldl_join_ge_mem _ _ e he

end Ledger
