import Mathlib.Data.ZMod.Basic
import Mathlib.Tactic.Ring
import Mathlib.Tactic.NormNum

namespace Dharma

abbrev Fp : Type := ZMod 3329
instance : Fact (Nat.Prime 3329) := ⟨by native_decide⟩

def butterfly (a b w : Fp) : Fp × Fp := (a + w * b, a - w * b)

theorem butterfly_sum (a b w : Fp) :
    (butterfly a b w).1 + (butterfly a b w).2 = 2 * a := by
  unfold butterfly; ring

theorem butterfly_diff (a b w : Fp) :
    (butterfly a b w).1 - (butterfly a b w).2 = 2 * w * b := by
  unfold butterfly; ring

end Dharma
