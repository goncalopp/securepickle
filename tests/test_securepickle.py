import pickle

try:
    from stringio import StringIO
except ImportError:
    from io import BytesIO as StringIO
import unittest

import securepickle

TEST_DATA = b"mydata"
TEST_KEY = b"mykey"
TEST_SIGNATURE = b"7daa03a2ebc25ab865460b8bbb9a896bec86139ec65ab71346313fda9d1471dee41d04f10c1ceef808006b999ec3be69d7576151172a1a699f7bf659ecfedc08"
TEST_SERIALIZED = b"securepickle|1.0|HMAC(SHA512)|7daa03a2ebc25ab865460b8bbb9a896bec86139ec65ab71346313fda9d1471dee41d04f10c1ceef808006b999ec3be69d7576151172a1a699f7bf659ecfedc08|mydata"


class SecurePickleTest(unittest.TestCase):
    def test_init(self):
        s = securepickle.SecurePickleData(b"", key=b"")
        self.assertEqual(s.valid, True)  # No signature

    def test_init_with_signature(self):
        # Creating a SecurePickleData with a signature automatically verifies it
        with self.assertRaises(securepickle.InvalidSignatureError):
            s = securepickle.SecurePickleData(b"", signature=b"", key=b"")
        # ... but not if validate = False
        s = securepickle.SecurePickleData(b"", signature=b"", key=b"", validate=False)
        self.assertEqual(s.valid, False)
        # Accessing unvalidated data
        with self.assertRaises(securepickle.UnvalidatedError):
            s.pickled_data

    def test_validate_invalid(self):
        s = securepickle.SecurePickleData(b"", signature=b"", key=b"", validate=False)
        with self.assertRaises(securepickle.InvalidSignatureError):
            # verifying a invalid signature fails
            s.validate()
        with self.assertRaises(securepickle.UnvalidatedError):
            # accessing unvalidated data after failed validate() fails
            s.pickled_data

    def test_validate_valid(self):
        s = securepickle.SecurePickleData(
            TEST_DATA, signature=TEST_SIGNATURE, key=TEST_KEY, validate=False
        )
        s.validate()
        self.assertEqual(s.pickled_data, TEST_DATA)

    def test_serialize(self):
        s = securepickle.SecurePickleData(TEST_DATA, key=TEST_KEY)
        self.assertEqual(s.serialize(), TEST_SERIALIZED)

    def test_deserialize_invalid(self):
        with self.assertRaises(securepickle.SecurePickleError):
            securepickle.SecurePickleData.deserialize(b"randomdata", b"randomkey")

    def test_deserialize_valid(self):
        d = securepickle.SecurePickleData.deserialize(TEST_SERIALIZED, TEST_KEY)
        self.assertEqual(d.valid, True)
        self.assertEqual(d.header, b"securepickle")
        self.assertEqual(d.version, b"1.0")
        self.assertEqual(d.primitive, b"HMAC(SHA512)")
        self.assertEqual(d.signature, TEST_SIGNATURE)
        self.assertEqual(d.key, TEST_KEY)

    def test_deserialize_wrongkey(self):
        with self.assertRaises(securepickle.InvalidSignatureError):
            securepickle.SecurePickleData.deserialize(TEST_SERIALIZED, b"randomkey")


class ModuleTest(unittest.TestCase):
    def test_load_invalidkey(self):
        securepickle.set_key(b"")
        f = StringIO(TEST_SERIALIZED)
        with self.assertRaises(securepickle.InvalidSignatureError):
            securepickle.load(f)

    def test_load_valid(self):
        securepickle.set_key(TEST_KEY)
        obj1 = {"abc": 1}
        data = pickle.dumps(obj1)
        signature = securepickle.securepickle.sign(data, TEST_KEY)
        serialized = TEST_SERIALIZED.replace(TEST_DATA, data).replace(
            TEST_SIGNATURE, signature
        )
        f = StringIO(serialized)
        obj2 = securepickle.load(f)
        self.assertEqual(obj1, obj2)

    def test_dump(self):
        securepickle.set_key(TEST_KEY)
        obj = {"abc": 1}
        f = StringIO()
        securepickle.dump(obj, f)
        data = pickle.dumps(obj)
        signature = securepickle.securepickle.sign(data, TEST_KEY)
        expected = TEST_SERIALIZED.replace(TEST_DATA, data).replace(
            TEST_SIGNATURE, signature
        )
        self.assertEqual(f.getvalue(), expected)


if __name__ == "__main__":
    unittest.main()
