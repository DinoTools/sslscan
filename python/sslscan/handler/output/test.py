from sslscan import output
from sslscan.handler import Output

class Test(Output):
    short_discription="Just some tests"
    description="""
    This handler is only used for development.
    """

    def __init__(self, foo=""):
        print(foo)

    def run(self, client, host_results):
        print("run test output")
        import pprint
        pprint.pprint(client)
        pprint.pprint(host_results)

output.register("test", Test)
