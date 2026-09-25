namespace Dharma
inductive Effect where
  | read | write | exfiltrate | hoard | dominate | destruct
  | network_access | exec | read_sensitive_path
  | read_outside_workdir | write_outside_workdir | exec_unvetted
  | network_unlisted
  deriving DecidableEq, Repr
end Dharma
