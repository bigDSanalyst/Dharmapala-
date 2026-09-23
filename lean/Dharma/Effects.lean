namespace Dharma
inductive Effect where
  | read | write | exfiltrate | hoard | dominate | destruct
  | network_access | exec | read_sensitive_path
  deriving DecidableEq, Repr
end Dharma
