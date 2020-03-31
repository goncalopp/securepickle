# securepickle

## Why should I use `securepickle` instead of `pickle?`

As the documentation for `pickle` [explains](https://docs.python.org/3/library/pickle.html), **pickle is insecure**. If you store pickled data in a database or filesystem that could be compromised or accessed by someone with malicious intentions, you should use `securepickle`. 

If you're not sure if you need it, it might be better to be safe than sorry.`securepickle` is a drop-in replacement for `pickle`, so you don't need to change any of your loading code.

## Why should I use `securepickle` instead of another secure pickling solution?
`securepickle` has 0 dependencies. It only uses the python standard library, and supports python 2 and 3.
`securepickle` has a documented file format and promises to be backward compatible. You will be able to unpickle your data even if the `securepickle` library or the used cryptographic primitives change.

## How do I use it?
```
import securepickle as pickle
# DON'T USE THIS KEY! Make sure to generate your own key randomly
securepickle.set_key("BO4cHKNaJE0GmiShTQ8mL8oSvqBDCx2q5Xdq7iNeCaU")

...

pickle.loads(...)
pickle.load(...)
pickle.dump(...)
pickle.dumps(...)
```

## Where should I store my key
Make sure you don't store the key in the same location of the pickled data. It's also recommended to not store the key on the source code.

## What kind of attacks does `securepickle` prevent

`securepickle` prevents [arbitrary code execution](https://en.wikipedia.org/wiki/Arbitrary_code_execution) from attackers that can modify (or directly influence) the pickled data.
This can happen, for example, if your database is compromised, or you store pickled files in a filesystem without regard to file access permissions.

`securepickle` does **NOT** prevent random people from unpickling the pickled data, even without the key. If this is a scenario you're concerned about, you should use standard database or disk encryption mechanisms. 

## What's the file format
```securepickle|<version>|<crypto primitive>|<signature>|<pickled data>```
List of crypto primitive strings supported:

  - `HMAC(SHA512)`

