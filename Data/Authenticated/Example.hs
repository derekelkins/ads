{-# LANGUAGE FlexibleContexts #-} 
{-# LANGUAGE TypeFamilies #-} 
{-# LANGUAGE StandaloneDeriving #-} 
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE UndecidableInstances #-}

--{-# LANGUAGE FlexibleInstances #-}
--{-# LANGUAGE TypeSynonymInstances #-}
module Data.Authenticated.Example where 
import qualified Crypto.Hash as Crypto
import Data.Authenticated
import Data.Authenticated.Fix
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as CBS
import Data.Monoid

-- Over-simplified Merkle Tree
data Bit = L | R
data Tree' x = Tip String | Bin x x
    deriving (Show, Functor)

instance Foldable Tree' where
    foldMap f (Tip _) = mempty
    foldMap f (Bin l r) = f l <> f r

type Tree = FixAuth Tree'
type AuthTree a = Auth (Tree a) a

bin :: (Authenticated a) => AuthTree a -> AuthTree a -> AuthTree a
bin l r = auth (FixAuth (Bin l r))

tip :: (Authenticated a) => String -> AuthTree a
tip s = auth (FixAuth (Tip s))

type TreeDigest = Crypto.Digest Crypto.SHA256

instance (Digestible t, Digest t ~ TreeDigest) => Digestible (Tree' t) where
    type Digest (Tree' a) = TreeDigest
    digest (Tip s) = Crypto.hash (CBS.pack s)
    digest (Bin l r) = Crypto.hashFinalize (Crypto.hashUpdate (Crypto.hashUpdate Crypto.hashInit (digest l)) (digest r))

-- For simplicity, assumes a complete tree.
fetch :: (Authenticated a, Monad (AuthM a (Tree a))) => [Bit] -> AuthTree a -> AuthM a (Tree a) String 
fetch ix t = do
    t' <- fmap unFixAuth (unauth t)
    case (ix, t') of
        ([]   , Tip s  ) -> return s
        (L:ix', Bin l _) -> fetch ix' l
        (R:ix', Bin _ r) -> fetch ix' r

update :: (Authenticated a, Monad (AuthM a (Tree a))) => [Bit] -> AuthTree a -> String -> AuthM a (Tree a) (AuthTree a)
update ix t s' = do
    t' <- fmap unFixAuth (unauth t)
    case (ix, t') of
        ([]   , Tip s  ) -> return (tip s')
        (L:ix', Bin l r) -> do
            l' <- update ix' l s'
            return (bin l' r)
        (R:ix', Bin l r) -> do
            r' <- update ix' r s'
            return (bin l r')

exampleTree :: (Authenticated a) => AuthTree a
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

-- Red-Black+ Tree
data Color = Red | Black deriving (Show)
data RB a = RBTip | RBBin !Color (Auth (RB a) a) !Int (Maybe String) (Auth (RB a) a)
