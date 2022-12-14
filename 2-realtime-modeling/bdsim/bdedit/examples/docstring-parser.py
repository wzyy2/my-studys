import bdsim
import re
from collections import OrderedDict
import inspect
import importlib.util

re_isfield = re.compile(r'\s*:[a-zA-Zα-ωΑ-Ω0-9_ ]+:')
re_field = re.compile('^\s*:(?P<field>[a-zA-Z]+)(?: +(?P<var>[a-zA-Zα-ωΑ-Ω0-9_]+))?:(?P<body>.+)$')
# a-zA-Zα-ωΑ-Ω0-9_
def indent(s):
    return len(s) - len(s.lstrip())


blocks = {}

fieldnames = ('param', 'type', 'input', 'output')
excludevars = ('kwargs', 'inputs')

# sim = bdsim.BDSim(verbose=True)
for package in ('bdsim', 'roboticstoolbox'):
    spec = importlib.util.find_spec('.blocks', package=package)
    m = spec.loader.load_module()
    path = m.__path__
    try:
       url = m.__dict__['url']
    except KeyError:
        url = None

    for name, block in m.__dict__.items():
        # check if it's a valid block class
        if not inspect.isclass(block):
            continue
        if inspect.getmro(block)[-2].__name__ != 'Block':
            continue
        if name.endswith('Block'):
            continue

        # create a dict of block info
        block_info = {}
        block_info['path'] = path  # path to folder holding block definition
        block_info['classname'] = name
        if url is not None:
            block_info['url'] = url + "#" + block.__module__ + "." + name
        block_info['class'] = block
        block_info['module'] = block.__module__
        block_info['package'] = package

        # get the docstring
        ds = block.__init__.__doc__ #inspect.getdoc(block)

        # parse out all lines of the form:
        #
        #  :field var: body
        # or
        #  :field var: body with a very long description that
        #       carries over to another line or two
        fieldlines = []
        for para in ds.split('\n\n'):
            # print(para)
            # print('--')

            indent_prev = None
            infield = False

            for line in para.split('\n'):
                if len(line) == 0:
                    continue
                if indent_prev is None:
                    indent_prev = indent(line)
                if re_isfield.match(line) is not None:
                    fieldlines.append(line.lstrip())
                    infield = True
                if indent(line) > indent_prev and infield:
                    fieldlines[-1] += ' ' + line.lstrip()
                if indent(line) == indent_prev:
                    infield = False

        # fieldlines is a list of lines of the form
        #
        #   :field var: body
        #
        # where extension lines have been concatenated

        # create a dict of dicts
        #
        #   dict[field][var] -> body
        dict = OrderedDict()

        for line in fieldlines:
            m = re_field.match(line)
            if m is not None:
                if name == 'Bicycle':
                    z= 3
                field, var, body = m.groups()
                if var in excludevars or field not in fieldnames:
                    continue
                if field not in dict:
                    dict[field] = {var: body}
                else:
                    dict[field][var] = body
                dict[m.group('field')]

        # now connect pairs of lines of the form
        #
        # :param X: param description
        # :type X: type description
        #
        # params[X] = (type description, param description)
        params = {}
        if 'param' in dict:
            for var, descrip in dict['param'].items():
                typ = dict['type'].get(var, None)
                params[var] = (typ, descrip)

        # now add all the other stuff we know about the block
        block_info['params'] = params
        block_info['inputs'] = dict.get('input')
        block_info['outputs'] = dict.get('output')

        # try:
        #     instance = block()
        #     block_info['nin'] = instance.nin
        #     block_info['nout'] = instance.nout
        #     block_info['blockclass'] = instance.blockclass
        # except:

        # print('couldnt instantiate ', name)
        block_info['nin'] = block.nin
        block_info['nout'] = block.nout
        blockclass = block.__base__.__name__.lower().replace('block', '')
        block_info['blockclass'] = blockclass

        blocks[name] = block_info

print(blocks['Bicycle'])
for k, v in blocks['Bicycle']['inputs'].items():
    print(k, v)
for k, v in blocks['Bicycle']['outputs'].items():
    print(k, v)
# for k, v in blocks['Gain'].items():
#     print(k, ':', v)
## build all bdedit blocks

# map = {
#         'source': SourceBlock,
#         'transfer': TransferBlock,
# }

# for block in blocks:

#     class = map[block['blockclass']]
#     # set its parameters, limits, types etc
#     # set the url
#     # set the icon path
