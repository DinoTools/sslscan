from sslscan import output
from sslscan.handler import Output

class Legacy(Output):
    short_description = "Legacy output (sslscan < 1.11)"
    help = """
    Support legacy output format
    """

    def __init__(self, config_string=None):
        Output.__init__(self)
        self.config.load_string(config_string)

    def _print_client_ciphers(self, client):
        print("  Supported Client Cipher(s):")
        for cipher in client.get("ciphers", []):
            print("    %s" % cipher.get("name", ""))
        print("")

    def _print_host_certificate(self, host):
        x509 = host.get("certificate.x509", None)
        if x509 is None:
            return

        print("")
        print("  SSL Certificate:")
        print("    Certificate blob:")
        print(x509.get_certificate_blob())
        print("    Version: %lu" % x509.get_version())
        tmp = x509.get_serial_number()
        print("    Serial Number: %lu (0x%lx)" % (tmp, tmp))
        print("    Signature Algorithm: %s" % x509.get_signature_algorithm())
        print("    Issuer: %s" % x509.get_issuer())
        print("    Not valid before: %s" % x509.get_not_before(3))
        print("    Not valid after: %s" % x509.get_not_after(3))
        print("    Subject: %s" % x509.get_subject())
        pk = x509.get_public_key()
        if pk:
            print("    Public Key Algorithm: %s" % pk.get_algorithm())
            tmp_name = pk.get_type_name()
            if tmp_name:
                tmp_bits = pk.get_bits()
                if tmp_bits:
                    print("    %s Public Key: (%d bit)" % (tmp_name, tmp_bits))
                else:
                    print("    %s Public Key:" % tmp_name)
                print(pk.get_key_print(6))
            else:
                print("    Public Key: Unknown")
        else:
            print("   Public Key: Could not load")

        print("    X509v3 Extensions:")
        extensions = x509.get_extensions()
        if extensions:
            for ext in extensions:
                print(
                    "      %s: %s" % (
                        ext.get_name(),
                        "critical" if ext.get_critical() else ""
                    )
                )
                print(ext.get_value(8))

        print("  Verify Certificate:")
        verfy_status = host.get("certificate.verify.status", None)
        if verfy_status:
            print("    Certificate passed verification")
        else:
            print("    %s" % host.get("certificate.verify.error_message", ""))

    def _print_host_ciphers(self, host):
        print("  Supported Server Cipher(s):")
        for cipher in host.get("ciphers", []):
            print(
                "    %-9s %-6s %-9s %s" % (
                    cipher.get_status_name().capitalize(),
                    cipher.get_method_name(),
                    "%d bits" % cipher.get_bits(),
                    cipher.get_name()
                )
            )
        print("")

    def _print_host_preferred_cipers(self, host):
        print("  Preferred Server Cipher(s):")
        for cipher in host.get("ciphers.default", {}).values():
            if cipher is None:
                continue
            print(
                "    %-6s %-9s %s" % (
                    cipher.get_method_name(),
                    "%d bits" % cipher.get_bits(),
                    cipher.get_name()
                )
            )

    def _print_host_renegotiation(self, host):
        if host.get("renegotiation.supported", None) is None:
            return

        print("  TLS renegotiation:")
        if host.get("renegotiation.secure", None):
            print("    Secure session renegotiation supported")
        elif host.get("renegotiation.supported", None):
            print("    Insecure session renegotiation supported")
        elif host.get("renegotiation.supported", None) is not None:
            print("    Session renegotiation not supported\n\n")
        print("")

    def run(self, client, host_results):
        if self.config.get_value("show-client-ciphers"):
            self._print_client_ciphers(client)

        for host in host_results:
            if self.config.get_value("show-host-ciphers"):
                self._print_host_ciphers(host)

            if self.config.get_value("show-host-renegotiation"):
                self._print_host_renegotiation(host)

            if self.config.get_value("show-host-preferred-ciphers"):
                self._print_host_preferred_cipers(host)

            if self.config.get_value("show-host-certificate"):
                self._print_host_certificate(host)

output.register("legacy", Legacy)
