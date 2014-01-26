import os
import re
import textwrap


class OutputManager(object):
    def __init__(self):
        self.registered = {}
        self.active = []

    def load_handler(self, name, config_string):
        handler = self.registered.get(name, None)
        print(handler)
        if handler is None:
            # ToDo: error handling
            return
        handler = handler(config_string)
        if handler is None:
            # ToDo: error handling
            return
        self.active.append(handler)

    def load_from_string(self, data):
        name, sep, config_string = data.partition(":")
        return self.load_handler(name, config_string)

    def print_help(self, name=None):
        names = [name]
        if name is None:
            names = list(self.registered.keys())
        names.sort()
        for n in names:
            text = getattr(self.registered[n], "description", "")
            print(n)
            print(text)
        return True

    def print_help_verbose(self, name=None):
        names = [name]
        if name is None:
            names = list(self.registered.keys())
        names.sort()
        for name in names:
            print(name)
            print()
            handler = self.registered.get(name, None)
            text = getattr(handler, "help", None)
            if text is not None:
                txt = DocWrapper(
                    initial_indent=" " * 4,
                    subsequent_indent=" " * 4,
                    width=75
                )
                text = textwrap.dedent(text).strip()
                print("\n".join(txt.wrap(text)))
                print()
            obj = handler()
            if obj is not None:
                obj.config.print_help()

        return True

    def print_list(self):
        names = list(self.registered.keys())
        names.sort()
        for name in names:
            text = getattr(self.registered[name], "short_description", "")
            print("%.10s - %s" % (name, text))
        return 0

    def register(self, name, cls):
        if name in self.registered:
            # ToDo: error handling
            return
        self.registered[name] = cls

    def run(self, client, host_results):
        handlers = self.active
        if len(handlers) == 0:
            tmp = self.registered.get("legacy", None)
            if tmp is None:
                return 1
            handlers = [tmp()]

        for h in handlers:
            h.run(client, host_results)
        return 0

class ServiceManager(object):
    def __init__(self):
        self.registered = {}
        self.default = None

    def register(self, name, obj):
        if name in self.registered:
            # ToDo: error handling
            return
        self.registered[name] = obj

    def set_default(self, name, config_string):
        srv = self.registered.get(name, None)
        if srv is None:
            # ToDo: error handling
            return
        srv = srv.from_string(config_string)
        if srv is None:
            # ToDo: error handling
            return
        self.registered[name] = srv

class Option(object):
    def __init__(self, name, action="store", default=None, help="", metavar="", type="string", negation=None):
        self.name = name
        self.action = action
        self.default = default
        self.help = help
        self.metavar = metavar
        self.negation = negation
        self.value = None
        self.type = type

    def convert_value_type(self, value):
        if self.type == "bool":
            if type(value) == int:
                return bool(value)
            if type(value) != str:
                value = str(value)
            value = value.strip().lower()
            return value in ["1", "true", "yes"]

        if self.type == "int":
            return int(value)

        if self.type == "float":
            return float(value)

        return value

    def get_value(self, default=None):
        if self.value is not None:
            return self.value
        if default is not None:
            return default
        return self.default

    def print_help(self, name_prefix=""):
        default = str(self.default)
        if self.type == "bool":
            default = "1" if self.default else "0"

        tmp = {
            "default": default,
            "name": self.name,
            "name_negation": self.negation,
            "name_prefix": name_prefix,
            "type": self.type
        }
        if self.type == "bool":
            if self.negation is not None:
                print("  {name_prefix}{name_negation}".format(**tmp))
            print("  {name_prefix}{name}".format(**tmp))

        print(
            "  {0} (Default: {default})".format(
                "{name_prefix}{name}=[{type}]".format(**tmp),
                **tmp
            )
        )
        txt = textwrap.TextWrapper(
            initial_indent=" " * 20,
            subsequent_indent=" " * 20,
            width=69
        )
        print(txt.fill(self.help))
        print()

    def set_value(self, value):
        value = self.convert_value_type(value)

        if self.action == "store":
            self.value = value
            return True

        if self.action == "append":
            if type(self.value) is not list:
                self.value = []
            self.value.append(value)
            return True

        return False


class BaseConfig(object):
    def __init__(self):
        self._option_map = {}
        self._options = []
        self._option_groups = []

    def add_option(self, name, **kwargs):
        if name in self._option_map:
            return False
        option = Option(name, **kwargs)
        self._option_map[name] = option
        if option.type == "bool" and option.negation is not None:
            self._option_map[option.negation] = name
        self._options.append(option)

    def add_option_group(self, group):
        option_map = group.get_option_map()
        for name in option_map.keys():
            if name in self._option_map:
                return False
        self._option_map.update(option_map)
        self._option_groups.append(group)

    def get_option(self, name):
        return self._option_map.get(name, None)

    def get_option_map(self):
        return self._option_map

    def get_value(self, name, default=None):
        option = self.get_option(name)
        if option is None:
            return None
        return option.get_value(default=default)

    def set_value(self, name, value):
        option = self._option_map.get(name, None)
        if option is None:
            return False

        negate = False
        if type(option) == str:
            option = self._mapped_global_options.get(name, None)
            negate = True

        if option is None:
            return False

        value = option.convert_value_type(value)
        if option.type == "bool" and negate is True:
            value = not value

        return option.set_value(value)

    def set_value_from_string(self, data):
        name, sep, value = data.partition("=")
        if name is None or name == "":
            return False

        negation = False
        option = self._option_map.get(name, None)
        if type(option) is str:
            negation = True
            option = self._option_map.get(option, None)

        if option is None:
            return False

        if option.type == "bool" and sep == "":
            value = not negation

        return option.set_value(value)


class OptionGroup(BaseConfig):
    def __init__(self, label, help=None):
        BaseConfig.__init__(self)
        self.label = label
        self.help = help

    def print_help(self, name_prefix=""):
        txt = textwrap.TextWrapper(
            initial_indent=" " * 4,
            subsequent_indent=" " * 4,
            width=75
        )
        print("{0}:".format(self.label))
        if self.help is not None:
            print(txt.fill(self.help))
        print()

        for option in self._options:
            option.print_help(name_prefix=name_prefix)


class GlobalConfig(BaseConfig):
    def print_help(self):
        for option in self._options:
            option.print_help(name_prefix="--")

        for group in self._option_groups:
            group.print_help(name_prefix="--")


class HandlerConfig(BaseConfig):
    def __init__(self, global_config):
        BaseConfig.__init__(self)
        self._options = []
        self._global_config = global_config
        self._mapped_global_options = {}

    def get_value(self, name):
        # process global options
        option = self._mapped_global_options.get(name, None)
        if option is not None:
            if option["value"] is not None:
                return option["value"]
            return option["option"].get_value(option["default"])

        # process local options
        option = self._option_map.get(name, None)
        if option is None:
            return None
        return option.get_value()

    def print_help(self, name_prefix=""):
        print("Global options:")
        names = list(self._mapped_global_options.keys())
        names.sort()
        for name in names:
            option = self._mapped_global_options.get(name)
            if type(option) == str:
                continue
            option["option"].print_help(name_prefix=name_prefix)

        if len(self._options) > 0:
            print("Handler options:")
            print()
            for option in self._options:
                option.print_help(name_prefix=name_prefix)

        if len(self._option_groups) > 0:
            print()
            for group in self._option_groups:
                group.print_help(name_prefix=name_prefix)

    def set_value(self, name, value):
        # process global options
        option = self._mapped_global_options.get(name, None)
        negate = False
        if type(option) == str:
            option = self._mapped_global_options.get(name, None)
            negate = True

        if option is not None:
            value = option["option"].convert_value_type(value)
            if option.type == "bool" and negate is True:
                value = not value
            option["value"] = value
            return True

        return BaseConfig.set_value(self, name, value)

    def load_string(self, config_string):
        """
        Parse config string and create the object.

        :param cls: Class
        :param config_string: String to parse
        :return: Object or None

        """
        if config_string is None:
            return True

        for option in config_string.split(":"):
            if not self.set_value_from_string(option):
                return False

        return True


class OutputConfig(HandlerConfig):
    def __init__(self, global_config, global_defaults=None):
        if global_defaults is None:
            global_defaults = {}
        HandlerConfig.__init__(self, global_config)
        names = [
            "show-client-ciphers",
            "show-host-certificate",
            "show-host-ciphers",
            "show-host-preferred-ciphers",
            "show-host-renegotiation"
        ]
        for name in names:
            option = global_config.get_option(name)
            if option is None:
                continue
            self._mapped_global_options[name] = {
                "default": global_defaults.get(name, None),
                "option": option,
                "value": None
            }
            if option.type == "bool" and option.negation is not None:
                self._mapped_global_options[option.negation] = name

class DocWrapper(textwrap.TextWrapper):
    def wrap(self, text):
        para_edge = re.compile(r"(\n\s*\n)", re.MULTILINE)
        paragraphs = para_edge.split(text)
        wrapped_lines = []
        for para in paragraphs:
            if para.isspace():
                if not self.replace_whitespace:
                    if self.expand_tabs:
                        para = para.expandtabs()
                    wrapped_lines.append(para[1:-1])
                else:
                    wrapped_lines.append('')
            else:
                wrapped_lines.extend(textwrap.TextWrapper.wrap(self, para))
        return wrapped_lines

def load_handlers():
    import sslscan.handler.output
    path = sslscan.handler.output.__path__[0]
    for filename in os.listdir(path):
        if filename == "__init__.py":
            continue

        pkg = None
        if os.path.isdir(os.path.join(path, filename)) and \
           os.path.exists(os.path.join(path, filename, "__init__.py")):
            pkg = filename

        if filename[-3:] == '.py':
            pkg = filename[:-3]

        if pkg is None:
            continue

        try:
            __import__("sslscan.handler.output." + pkg, locals(), globals())
            print("Loaded '{pkg}' successfully".format(pkg=pkg))
        except Exception as msg:
            print(str(msg))

output = OutputManager()
service = ServiceManager()
config = GlobalConfig()

output_options = OptionGroup(
    label="Global output handler options"
)

output_options.add_option(
    "show-client-ciphers",
    default=False,
    negation="hide-client-ciphers",
    help="Show supported client ciphers",
    type="bool"
)

output_options.add_option(
    "show-host-certificate",
    help="Show certificate information",
    negation="hide-host-certificate",
    default=True,
    type="bool"
)

output_options.add_option(
    "show-host-ciphers",
    help="Show host ciphers",
    negation="hide-host-ciphers",
    default=True,
    type="bool"
)

output_options.add_option(
    "show-host-preferred-ciphers",
    help="Show preferred ciphers",
    negation="hide-host-preferred-ciphers",
    default=True,
    type="bool"
)

output_options.add_option(
    "show-host-renegotiation",
    help="Show renegotiation information",
    negation="hide-host-renegotiation",
    default=True,
    type="bool"
)

config.add_option_group(output_options)
