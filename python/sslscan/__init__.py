import os


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
        handler = handler.from_string(config_string)
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
        for n in names:
            text = getattr(self.registered[n], "description", "")
            print(n)
            print(text)
        return 0

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
        for h in self.active:
            h.run(client, host_results)

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
