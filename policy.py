
# What a deployment decides, kept apart from what the code knows.
#
# The Vow says which effects are forbidden. The policy says what the words
# mean here: which paths are sensitive, which commands are vetted, which hosts
# are in scope and which are exfiltration sinks, how many writes are hoarding.
# Two deployments can hold the same Vow and mean different things by
# read_sensitive_path; a verdict is only checkable if it says which meaning
# judged it. So a policy is data with a hash, the run record carries it, the
# decision and the attestation name its hash (signed), and a co-signer
# re-derives effects under the policy the record carries and refuses one it
# was not configured to accept.
#
# What stays in code is knowledge about programs, not choices about them: that
# curl is a network command, cat reads its operands, apt fetches packages.
#
# File format (JSON, every key optional, unknown keys refused):
#   {"format": "dharmapala-policy/v1",
#    "sensitive_paths": [regex, ...],     # a read of a matching path is read_sensitive_path
#    "vetted_commands": [name, ...],      # anything else run is exec_unvetted
#    "allowed_hosts":   [host, ...],      # anything else reached is network_unlisted
#    "exfil_hosts":     [host, ...],      # reaching one of these is exfiltrate
#    "hoard_threshold": int}              # this many writes in one plan is hoard
# A key left out keeps the default below; a key given replaces it (it does
# not add to it), so a file says everything it means.
import hashlib, json, re
from dataclasses import dataclass, field

FORMAT = "dharmapala-policy/v1"

DEFAULTS = {
    "sensitive_paths": [r"^/etc/(passwd|shadow|sudoers)$", r"^/root(/|$)", r"(^|/)\.ssh(/|$)"],
    "vetted_commands": ["cat", "date", "echo", "grep", "head", "ls", "pwd", "sort", "tail",
                        "true", "uniq", "wc"],
    "allowed_hosts": [],                         # default-deny: no host is in scope unless listed
    "exfil_hosts": ["evil.example.com", "pastebin.com", "transfer.sh"],
    "hoard_threshold": 3,
}

class PolicyError(ValueError): pass

@dataclass(frozen=True)
class Policy:
    sensitive_paths: tuple; vetted_commands: frozenset
    allowed_hosts: tuple; exfil_hosts: tuple; hoard_threshold: int
    _sensitive: object = field(default=None, repr=False, compare=False)

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict): raise PolicyError("a policy is a JSON object")
        if data.get("format", FORMAT) != FORMAT:
            raise PolicyError(f"not a {FORMAT} policy: format {data.get('format')!r}")
        unknown = set(data) - set(DEFAULTS) - {"format"}
        if unknown: raise PolicyError(f"unknown policy keys: {', '.join(sorted(unknown))}")
        v = {**DEFAULTS, **{k: data[k] for k in DEFAULTS if k in data}}
        for k in ("sensitive_paths", "vetted_commands", "allowed_hosts", "exfil_hosts"):
            if not isinstance(v[k], list) or not all(isinstance(x, str) and x for x in v[k]):
                raise PolicyError(f"{k} must be a list of non-empty strings")
        if not isinstance(v["hoard_threshold"], int) or isinstance(v["hoard_threshold"], bool) \
                or v["hoard_threshold"] < 1:
            raise PolicyError("hoard_threshold must be a positive integer")
        try: sensitive = re.compile("|".join(f"(?:{p})" for p in v["sensitive_paths"])) \
            if v["sensitive_paths"] else None
        except re.error as e: raise PolicyError(f"sensitive_paths: {e}") from None
        return cls(tuple(v["sensitive_paths"]), frozenset(v["vetted_commands"]),
                   tuple(h.lower().rstrip(".") for h in v["allowed_hosts"]),
                   tuple(h.lower().rstrip(".") for h in v["exfil_hosts"]),
                   v["hoard_threshold"], sensitive)

    @classmethod
    def load(cls, path):
        try: data = json.loads(open(path).read())
        except (OSError, ValueError) as e: raise PolicyError(f"{path}: {e}") from None
        return cls.from_dict(data)

    def is_sensitive(self, path):
        return self._sensitive is not None and bool(self._sensitive.search(path))

    def to_dict(self):
        return {"format": FORMAT, "sensitive_paths": list(self.sensitive_paths),
                "vetted_commands": sorted(self.vetted_commands),
                "allowed_hosts": list(self.allowed_hosts), "exfil_hosts": list(self.exfil_hosts),
                "hoard_threshold": self.hoard_threshold}

    def hash(self):
        return hashlib.sha256(json.dumps(self.to_dict(), sort_keys=True,
                                         separators=(",", ":")).encode()).hexdigest()

DEFAULT = Policy.from_dict({})

def of(policy):
    """None means the default; a dict is a policy's to_dict() (as a run record carries it)."""
    if policy is None: return DEFAULT
    if isinstance(policy, Policy): return policy
    return Policy.from_dict(policy)
