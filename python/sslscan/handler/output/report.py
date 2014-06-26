from sslscan import output, Color
from sslscan.handler import Output, output as output_helper

class Report(Output):
    short_description = "Generate report"
    help = """
    """

    def __init__(self, config_string=None):
        Output.__init__(self)
        self.config.load_string(config_string)
        self.color = Color(config=self.config)

    def _print_client_ciphers(self, client):
        print("  Supported Client Cipher(s):")
        for cipher in client.get("ciphers", []):
            color_args = (cipher, self.config, self.color)
            color_code_bits = output_helper.get_cipher_bits_color(*color_args)
            color_code_method_name = output_helper.get_cipher_method_name_color(*color_args)
            color_code_name = output_helper.get_cipher_name_color(*color_args)
            print(
                "    {3}{0:5}{6} {4}{1:9}{6} {5}{2}{6}".format(
                    cipher.get_method_name(),
                    "%d bits" % cipher.get_bits(),
                    cipher.get_name(),
                    color_code_method_name,
                    color_code_bits,
                    color_code_name,
                    self.color.RESET
                )
            )
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
            color_args = (cipher, self.config, self.color)
            color_code_bits = output_helper.get_cipher_bits_color(*color_args)
            color_code_method_name = output_helper.get_cipher_method_name_color(*color_args)
            color_code_name = output_helper.get_cipher_name_color(*color_args)

            alert_info = ""
            alerts = cipher.get_alerts()
            if len(alerts) > 0:
                # Show only first alert
                alert_info = "({0}: {1})".format(alerts[0].get_type(), alerts[0].get_description())
            print(
                "    {0:9} {5}{1:6}{8} {6}{2:9}{8} {7}{3}{8}  {4}".format(
                    cipher.get_status_name().capitalize(),
                    cipher.get_method_name(),
                    "%d bits" % cipher.get_bits(),
                    cipher.get_name(),
                    alert_info,
                    color_code_method_name,
                    color_code_bits,
                    color_code_name,
                    self.color.RESET
                )
            )
        print("")

    def _print_host_preferred_cipers(self, host):
        print("  Preferred Server Cipher(s):")
        for cipher in host.get("ciphers.default", {}).values():
            if cipher is None:
                continue
            color_args = (cipher, self.config, self.color)
            color_code_bits = output_helper.get_cipher_bits_color(*color_args)
            color_code_method_name = output_helper.get_cipher_method_name_color(*color_args)
            color_code_name = output_helper.get_cipher_name_color(*color_args)

            alert_info = ""
            alerts = cipher.get_alerts()
            if len(alerts) > 0:
                # Show only first alert
                alert_info = "({0}: {1})".format(alerts[0].get_type(), alerts[0].get_description())
            print(
                "    {4}{0:6}{7} {5}{1:9}{7} {6}{2}{7} {3}".format(
                    cipher.get_method_name(),
                    "%d bits" % cipher.get_bits(),
                    cipher.get_name(),
                    alert_info,
                    color_code_method_name,
                    color_code_bits,
                    color_code_name,
                    self.color.RESET
                )
            )
        print("")

    def _print_host_renegotiation(self, host):
        if host.get("renegotiation.supported", None) is None:
            return

        color_renegotiation = output_helper.get_renegotiation_color(
            host,
            self.config,
            self.color
        )
        print("  TLS renegotiation:")
        msg = ""
        if host.get("renegotiation.secure", None):
            msg = "    {0}Secure session renegotiation supported{1}"
        elif host.get("renegotiation.supported", None):
            msg = "    {0}Insecure session renegotiation supported{1}"
        elif host.get("renegotiation.supported", None) is not None:
            msg = "    {0}Session renegotiation not supported{1}"

        print(msg.format(color_renegotiation, self.color.RESET))
        print("")

    def _print_host_session(self, host):
        print("  Session:")

        compression = host.get("session.compression", None)
        if not compression:
            compression = "None"
        print("    Compression: {0}".format(compression))

        expansion = host.get("session.expansion", None)
        if not expansion:
            expansion = "None"
        print("    Expansion: {0}".format(expansion))

        print("")

    def _print_vulnerability(self, host):
        vul_heartbleed = host.get("vulnerability.heartbleed")
        if vul_heartbleed is not None:
            print("  Heartbleed: {0}".format("vulnerable" if vul_heartbleed else "not vulnerable"))

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

            if self.config.get_value("show-host-session"):
                self._print_host_session(host)

            if self.config.get_value("show-host-certificate"):
                self._print_host_certificate(host)

            self._print_vulnerability(host)

output.register("report", Report)
