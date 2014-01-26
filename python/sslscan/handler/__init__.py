from sslscan import OutputConfig, config as g_config


class Output(object):

    """Base class for all output handler."""

    def __init__(self, config_string=None):
        self.config = OutputConfig(g_config)

    def run(self, client, host_results):
        """
        Output the results.

        :param client: Client information
        :param host_results: List of host scan results

        """
        pass

    @classmethod
    def from_string(cls, config_string):
        """
        Parse config string and create the object.

        :param cls: Class
        :param config_string: String to parse
        :return: Object or None

        """
        options = {}
        for p in config_string.split(":"):
            name, sep, value = p.partition("=")
            if name is None or name == "":
                continue
            options[name] = value
        # ToDo: do some checks
        return cls(**options)
