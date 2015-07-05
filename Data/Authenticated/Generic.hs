{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE FlexibleInstances #-}

-- For testing
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}
module Data.Authenticated.Generic where
import GHC.Generics
import Data.Authenticated

-- For example
import qualified Crypto.Hash as Crypto
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as CBS

newtype Auth1 f a = Auth1 { getAuth1 :: Auth (f a) a }
-- These two instances are what requires UndecidableInstances.
instance (Show (f Prover), Show (Digest (f Prover))) => Show (Auth1 f Prover) where
    showsPrec n = showsPrec n . getAuth1
instance (Show (f Verifier), Show (Digest (f Verifier))) => Show (Auth1 f Verifier) where
    showsPrec n = showsPrec n . getAuth1

--class GMapAuth f where    

-- Example

data Bit = L | R
data Tree a = Tip String | Bin (Auth1 Tree a) (Auth1 Tree a)
    deriving (Generic1)

bin :: (Authenticated a) => Auth1 Tree a -> Auth1 Tree a -> Auth1 Tree a
bin l r = Auth1 (auth (Bin l r))

tip :: (Authenticated a) => String -> Auth1 Tree a
tip s = Auth1 (auth (Tip s))

instance (Digestible (Auth (Tree a) a)) => Digestible (Tree a) where
    type Digest (Tree a) = Crypto.Digest Crypto.SHA256
    digest (Tip s) = Crypto.hash (CBS.pack s)
    digest (Bin (getAuth1 -> l) (getAuth1 -> r)) = Crypto.hashFinalize (Crypto.hashUpdate (Crypto.hashUpdate Crypto.hashInit (digest l)) (digest r))

-- TODO: Make a generic function to handle this.
instance MapAuth Tree where
    mapAuth (Tip s) = Tip s
    mapAuth (Bin (getAuth1 -> l) (getAuth1 -> r)) = Bin (Auth1 (shallowAuth l)) (Auth1 (shallowAuth r))

-- For simplicity, assumes a complete tree.
fetch :: (Authenticated a, Monad (AuthM a (Tree a))) => [Bit] -> Auth1 Tree a -> AuthM a (Tree a) String 
fetch ix t = do
    t' <- unauth (getAuth1 t)
    case (ix, t') of
        ([]   , Tip s  ) -> return s
        (L:ix', Bin l _) -> fetch ix' l
        (R:ix', Bin _ r) -> fetch ix' r

update :: (Authenticated a, Monad (AuthM a (Tree a))) => [Bit] -> Auth1 Tree a -> String -> AuthM a (Tree a) (Auth1 Tree a)
update ix t s' = do
    t' <- unauth (getAuth1 t)
    case (ix, t') of
        ([]   , Tip s  ) -> return (tip s')
        (L:ix', Bin l r) -> do
            l' <- update ix' l s'
            return (bin l' r)
        (R:ix', Bin l r) -> do
            r' <- update ix' r s'
            return (bin l r')

exampleTree :: (Authenticated a) => Auth1 Tree a
exampleTree = bin (bin (tip "ll") (tip "lr")) (bin (tip "rl") (tip "rr"))

-- Realistically, the verifier would run on a client who would fetch exampleTree :: Auth (Tree 'Verifier) 'Verifier,
-- which is just a single hash from a trusted source.  The (untrusted) prover would run on a server and return a [Tree 'Verifier] 
-- which is a list of shallow trees (i.e. a list of hashes terminating in a Tip which holds the result in this case).  The client
-- would run the verifier and, if successful, get back a verified result.

works :: Maybe String
works = runVerifier (fetch [R,L] exampleTree) ps' -- Note, exampleTree here is just a top-level digest.
    where (_, ps) = runProver (fetch [R,L] exampleTree) -- exampleTree here is the full tree.
          ps' = map mapAuth ps -- Note, this is just a list of hashes plus a Tip at the end.

doesn'tWork :: Maybe String
doesn'tWork = runVerifier (fetch [R,R] exampleTree) ps' -- Note, exampleTree here is just a top-level digest.
    where (_, ps) = runProver (fetch [R,L] exampleTree) -- exampleTree here is the full tree.
          ps' = map mapAuth ps -- Note, this is just a list of hashes plus a Tip at the end.
