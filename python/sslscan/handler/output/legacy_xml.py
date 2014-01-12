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
        fp.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
        # ToDo: get version from core application
        fp.write("<document title=\"SSLScan Results\" version=\"1.10.0\" web=\"http://www.titania.co.uk\">\n")

        for host in host_results:
            # ToDo: get host and port from core application
            fp.write(" <ssltest host=\"\" port=\"\">\n")
            for cipher in client.get("ciphers", []):
                fp.write(" <client-cipher cipher=\"%s\" />\n" % cipher.get("name", ""))

            for cipher in host.get("ciphers", []):
                fp.write(
                    "  <cipher status=\"%s\" sslversion=\"%s\" bits=\"%d\" cipher=\"%s\" />\n" % (
                        cipher.get("status", "").capitalize(),
                        cipher.get("method.name", ""),
                        cipher.get("bits", 0),
                        cipher.get("name", "")
                    )
                )

            for cipher in host.get("ciphers.default", {}).values():
                if cipher is None:
                    continue
                fp.write(
                    "  <defaultcipher sslversion=\"%s\" bits=\"%d\" cipher=\"%s\" />\n" % (
                        cipher.get("method.name", ""),
                        cipher.get("bits", 0),
                        cipher.get("name", "")
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
            fp.write("  <not-valid-after>%s</not-valid-after>\n" % x509.get_not_before(3))
            fp.write("  <subject>%s</subject>\n" % x509.get_subject())
            fp.write("  <pk-algorithm>%s</pk-algorithm>\n" % host.get("certificate.public_key.algorithm", ""))
            pk_data = host.get("certificate.public_key.data", None)
            if pk_data is None:
                print("    Public Key: Could not load")
            else:
                pass  # ToDo
            fp.write(" </ssltest>\n")

        fp.write("</document>\n")
        fp.close()
        return 0

output.register("legacy-xml", LegacyXML)
