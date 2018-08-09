import functools
import collections
import logging
import pickle
import re
import sys

from ..core.smtlib import Expression, BitVecConstant


logger = logging.getLogger(__name__)


def issymbolic(value):
    '''
    Helper to determine whether an object is symbolic (e.g checking
    if data read from memory is symbolic)

    :param object value: object to check
    :return: whether `value` is symbolic
    :rtype: bool
    '''
    return isinstance(value, Expression)


def istainted(arg, taint=None):
    '''
    Helper to determine whether an object if tainted.
    :param arg: a value or Expression
    :param taint: a regular expression matching a taint value (eg. 'IMPORTANT.*'). If None this functions check for any taint value.
    '''

    if not issymbolic(arg):
        return False
    if taint is None:
        return len(arg.taint) != 0
    for arg_taint in arg.taint:
        m = re.match(taint, arg_taint, re.DOTALL | re.IGNORECASE)
        if m:
            return True
    return False


def get_taints(arg, taint=None):
    '''
    Helper to list an object taints.
    :param arg: a value or Expression
    :param taint: a regular expression matching a taint value (eg. 'IMPORTANT.*'). If None this functions check for any taint value.
    '''

    if not issymbolic(arg):
        return
    for arg_taint in arg.taint:
        if taint is not None:
            m = re.match(taint, arg_taint, re.DOTALL | re.IGNORECASE)
            if m:
                yield arg_taint
        else:
            yield arg_taint
    return


def taint_with(arg, taint, value_bits=256, index_bits=256):
    '''
    Helper to taint a value, Fixme this should not taint in place.
    :param arg: a value or Expression
    :param taint: a regular expression matching a taint value (eg. 'IMPORTANT.*'). If None this functions check for any taint value.
    '''
    if not issymbolic(arg):
        if isinstance(arg, int):
            arg = BitVecConstant(value_bits, arg)
    if not issymbolic(arg):
        raise ValueError("type not supported")
    arg._taint = arg.taint | frozenset((taint,))
    return arg


class memoized(object):
    '''Decorator. Caches a function's return value each time it is called.
    If called later with the same arguments, the cached value is returned
    (not reevaluated).
    '''

    def __init__(self, func):
        self.func = func
        self.cache = {}

    def __call__(self, *args, **kwargs):
        key = args + tuple(sorted(kwargs.items()))
        if not isinstance(key, collections.Hashable):
            # uncacheable. a list, for instance.
            # better to not cache than blow up.
            return self.func(*args, **kwargs)
        if key in self.cache:
            return self.cache[key]
        else:
            value = self.func(*args, **kwargs)
            self.cache[key] = value
            return value

    def __repr__(self):
        '''Return the function's docstring.'''
        return self.func.__doc__

    def __get__(self, obj, objtype):
        '''Support instance methods.'''
        return functools.partial(self.__call__, obj)


def is_binja_disassembler(disasm):
    return disasm == "binja-il"


class StateSerializer(object):
    """
    StateSerializer can serialize and deserialize :class:`~manticore.core.state.State` objects from and to
    stream-like objects.
    """

    def __init__(self):
        pass

    def serialize(self, state, f):
        raise NotImplementedError

    def deserialize(self, f):
        raise NotImplementedError


class PickleSerializer(StateSerializer):
    DEFAULT_RECURSION: int = 0x100000  # 1M
    MAX_RECURSION: int = 0x1000000  # 16.7M

    def __init__(self):
        super().__init__()
        sys.setrecursionlimit(PickleSerializer.DEFAULT_RECURSION)

    def serialize(self, state, f):
        try:
            f.write(pickle.dumps(state, 2))
        except RuntimeError:
            if sys.getrecursionlimit() >= PickleSerializer.MAX_RECURSION:
                raise Exception(f'PickleSerializer recursion limit surpassed {PickleSerializer.MAX_RECURSION}, aborting')
            logger.info(f'Recursion maximum {sys.getrecursionlimit()} hit, increasing')
            sys.setrecursionlimit(sys.getrecursionlimit() + PickleSerializer.DEFAULT_RECURSION)
            self.serialize(state, f)

    def deserialize(self, f):
        return pickle.load(f)