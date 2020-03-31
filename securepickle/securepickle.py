import pickle
import hashlib
import hmac

VERSION = b"1.0"
HEADER = b"securepickle"
SEPARATOR = b"|"
HMAC0 = b"HMAC(SHA512)"
SUPPORTED_CRYPTO = [HMAC0]

global_key = None


class SecurePickleError(Exception):
    """A generic error"""


class InvalidSignatureError(SecurePickleError):
    """A signature validation error"""


class UnvalidatedError(SecurePickleError):
    """Raised when trying to use pickled data that was not validated to be secure"""


class CompatibilityError(SecurePickleError):
    """Raise when using incompatible or unknown features"""


class SecurePickleData(object):
    def __init__(
        self,
        pickled_data,
        key,
        signature=None,
        header=HEADER,
        version=VERSION,
        primitive=HMAC0,
        validate=True,
    ):
        """Create a SecurePickleData object.
        If signature is set, it is validated (unless validate == False).
        """
        if key is None:
            raise SecurePickleError("Key is not set")
        if not isinstance(key, bytes):
            raise SecurePickleError("Key must be a bytes instance")
        if signature is not None and not isinstance(signature, bytes):
            raise SecurePickleError("Signature must be a bytes instance")
        if not isinstance(header, bytes):
            raise SecurePickleError("Header must be a bytes instance")
        if not isinstance(version, bytes):
            raise SecurePickleError("Version must be a bytes instance")
        if not isinstance(primitive, bytes):
            raise SecurePickleError("Primitive must be a bytes instance")
        self.signature = signature
        self.header = header
        self.version = version
        self.primitive = primitive
        self.key = key
        self._pickled_data = pickled_data
        if primitive not in SUPPORTED_CRYPTO:
            raise CompatibilityError("Unsupported crypto primitive: " + self.primitive.decode("ascii"))
        self.valid = False
        if self.signature is None:
            self.valid = True
        elif validate:
            self.validate()

    def validate(self):
        if self.primitive == HMAC0:
            expected = sign(self._pickled_data, self.key)
            if self.signature != expected:
                raise InvalidSignatureError(
                    "The data was signed by a different key. Expected {}, got {}".format(
                        expected, self.signature
                    )
                )
            self.valid = True
        else:
            raise CompatibilityError("Unsupported crypto primitive: " + self.primitive)

    def serialize(self):
        assert self.primitive == HMAC0
        signature = sign(self._pickled_data, self.key)
        return SEPARATOR.join(
            (self.header, self.version, self.primitive, signature, self.pickled_data,)
        )

    @property
    def pickled_data(self):
        if not self.valid:
            raise UnvalidatedError(
                "Please call validate() before accessing pickled_data"
            )
        return self._pickled_data

    @classmethod
    def deserialize(cls, serialized_data, key):
        if not serialized_data.startswith(HEADER):
            raise SecurePickleError("Not securepickle data (invalid header)")
        fields = ("header", "version", "primitive", "signature")
        values = {}
        i = 0
        assert len(SEPARATOR) == 1  # code below breaks otherwise
        for f in fields:
            next_i = serialized_data.index(SEPARATOR, i) + 1  # index of next field
            value = serialized_data[i : next_i - 1]  # don't include separator
            values[f] = value
            i = next_i
        values["pickled_data"] = serialized_data[i:]
        values["key"] = key
        return SecurePickleData(**values)  # checks signature


def sign(data, key):
    h = hmac.new(key, digestmod=hashlib.sha512)
    h.update(data)
    return h.hexdigest().encode("ascii")  # bytes


def loads(s):
    d = SecurePickleData.deserialize(s, global_key)
    return pickle.loads(d.pickled_data)


def load(f):
    return loads(f.read())


def dumps(obj):
    pickled_data = pickle.dumps(obj)
    d = SecurePickleData(pickled_data, key=global_key)
    return d.serialize()


def dump(obj, f):
    f.write(dumps(obj))


def set_key(key):
    global global_key
    global_key = key
