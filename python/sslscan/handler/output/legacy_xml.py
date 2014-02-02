from sslscan import output
from sslscan.handler import Output

class LegacyXML(Output):
    short_description = "Legacy XML output (sslscan < 1.11)"
    description = """
    Support legacy XML output format
    """

    def __init__(self, filename=""):
        self.filename = filename

    def run(self, client, host_results):
        fp = open(self.filename, "w")
        # ToDo: Could not open XML output file

        fp.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
        # ToDo: get version from core application
        fp.write("<document title=\"SSLScan Results\" version=\"1.10.0\" web=\"http://www.titania.co.uk\">\n")

        for host in host_results:
            # ToDo: get host and port from core application
            fp.write(" <ssltest host=\"\" port=\"\">\n")
            for cipher in client.get("ciphers", []):
                fp.write(" <client-cipher cipher=\"%s\" />\n" % cipher.get("name", ""))

            if host.get("renegotiation.supported", None) is not None:
                fp.write(
                    "  <renegotiation supported=\"%d\" secure=\"%d\" />\n" % (
                        host.get("renegotiation.supported", 0),
                        host.get("renegotiation.secure", 0)
                    )
                )

            for cipher in host.get("ciphers", []):
                fp.write(
                    "  <cipher status=\"%s\" sslversion=\"%s\" bits=\"%d\" cipher=\"%s\" />\n" % (
                        cipher.get_status_name().capitalize(),
                        cipher.get_method_name(),
                        cipher.get_bits(),
                        cipher.get_name()
                    )
                )

            for cipher in host.get("ciphers.default", {}).values():
                if cipher is None:
                    continue
                fp.write(
                    "  <defaultcipher sslversion=\"%s\" bits=\"%d\" cipher=\"%s\" />\n" % (
                        cipher.get_method_name(),
                        cipher.get_bits(),
                        cipher.get_name()
                    )
                )

            x509 = host.get("certificate.x509", 0)
            fp.write("  <certificate>\n")
            fp.write("  <certificate-blob>\n%s</certificate-blob>\n" % (
                x509.get_certificate_blob()
            ))
            fp.write("   <version>%lu</version>\n" % x509.get_version())
            tmp = x509.get_serial_number()
            fp.write("  <serial>%lu (0x%lx)</serial>\n" % (tmp, tmp))
            fp.write("  <signature-algorithm>%s</signature-algorithm>\n" % x509.get_signature_algorithm())
            fp.write("  <issuer>%s</issuer>\n" % x509.get_issuer())
            fp.write("  <not-valid-before>%s</not-valid-before>\n" % x509.get_not_before(3))
            fp.write("  <not-valid-after>%s</not-valid-after>\n" % x509.get_not_after(3))
            fp.write("  <subject>%s</subject>\n" % x509.get_subject())
            pk = x509.get_public_key()
            if pk:
                fp.write("  <pk-algorithm>%s</pk-algorithm>\n" % pk.get_algorithm())
                tmp_name = pk.get_type_name()
                if tmp_name:
                    tmp_bits = pk.get_bits()
                    if tmp_bits:
                        fp.write("   <pk error=\"false\" type=\"%s\" bits=\"%d\">\n" % (tmp_name, tmp_bits))
                    else:
                        fp.write("   <pk error=\"false\" type=\"%s\">\n" % tmp_name)
                    print(pk.get_key_print(6))
                else:
                    fp.write("   <pk error=\"true\" type=\"unknown\" />\n")

            extensions = x509.get_extensions()
            if extensions:
                fp.write("   <X509v3-Extensions>\n")
                for ext in extensions:
                    fp.write(
                        "    <extension name=\"%s\"%s>%s</extension>\n" % (
                            ext.get_name(),
                            " level=\"critical\"" if ext.get_critical() else "",
                            ext.get_value(0)
                        ),
                    )
                fp.write("   </X509v3-Extensions>\n")

            fp.write(" </ssltest>\n")
        fp.write("</document>\n")
        fp.close()
        return 0

output.register("legacy-xml", LegacyXML)
