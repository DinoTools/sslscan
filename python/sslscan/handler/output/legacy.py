from sslscan import output
from sslscan.handler import Output

class Legacy(Output):
    def __init__(self, foo=""):
        print(foo)

    def run(self, client, host_results):
        print("  Supported Client Cipher(s):")
        for cipher in client.get("ciphers", []):
            print("    %s" % cipher.get("name", ""))
        print("")
        for host in host_results:
            print("  Supported Server Cipher(s):")
            for cipher in host.get("ciphers", []):
                print(
                    "    %-9s %-6s %-9s %s" % (
                        cipher.get("status", "").capitalize(),
                        cipher.get("method.name", ""),
                        "%d bits" % cipher.get("bits", 0),
                        cipher.get("name", "")
                    )
                )
            print("")
            print("  Preferred Server Cipher(s):")
            for cipher in host.get("ciphers.default", {}).values():
                if cipher is None:
                    continue
                print(
                    "    %-6s %-9s %s" % (
                        cipher.get("method.name", ""),
                        "%d bits" % cipher.get("bits", 0),
                        cipher.get("name", "")
                    )
                )
            print("")
            print("  SSL Certificate:")


output.register("legacy", Legacy)
