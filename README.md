Authenticated Data Structures
=============================

What it is
----------

This is an embedding into Haskell of the language described in 
[Authenticated Data Structures, Generically](http://www.cs.umd.edu/~amiller/gpads/). An example use-case would be implementing
a Merkle tree. It doesn't (currently) implement any of the optimizations described in the paper and, like the implementation 
described in the paper, does not support authenticated functions.

There are three methods for making an authenticated data with this library.  You can manually add `Auth` data types to your
structure and manually implement `MapAuth`.  You can represent your data structure as a fix point using `FixAuth` and it
will automatically be an instance of `MapAuth` as in [this example](https://github.com/derekelkins/ads/blob/master/Data/Authenticated/Example.hs).  
You can use `Auth1` data types and use derive `Generics1` and then simply state `instance MapAuth YourDataType`
(see [GHC Generics](https://hackage.haskell.org/package/base-4.8.0.0/docs/GHC-Generics.html) 
and [this example](https://github.com/derekelkins/ads/blob/master/Data/Authenticated/GenericExample.hs)).

All methods require implementing `Digestible` which should calculate a cryptographic digest of the data structure.

Operations over your data structure will be in the `AuthM` monad and the `Auth` data structure is introduced and eliminated
with `auth` and `unauth` respectively.  (`Auth1` is just a wrapper around `Auth`.)  The `AuthM` monad is parameterized by the
mode, `Prover` or `Verifier`, the type of the proof stream, and the return type of the monadic action.  Calling `runProver` on
an `AuthM` computation will return a pair containing the computations return value and the proof stream.  Typically, you would
serialize the proof stream and send it to a client on whose behalf you are doing the work.  The client would then call 
`runVerifier` on the same computation which results in a function which takes a proof stream and returns `Maybe` the result 
depending on whether the verification succeeds or not.

The representation of `Auth` (and thus data structures built on it) varies depending on the mode.  Typically, the client (verifier)
will have a top-level digest from a trusted source (this is what your data type will look like in Verifier mode) and will receive
a proof stream from an untrusted server (prover) claiming to have performed the operation on the client's behalf.  The proof stream 
will typically be tantamount to a stream of hashes which the client will use to verify the integrity of the computation.

As a concrete example, if a client wants to request a value from an untrusted server mirroring a large Merkle tree, then the client
can do that and verify correctness without needing, itself, to store all of the Merkle tree.  All the client would need is the
top-level hash of the Merkle tree from a trusted source, and the stream of hashes from the untrusted mirror which will be 
logarithmic in the size of the Merkle tree.
