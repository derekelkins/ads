{-# LANGUAGE StandaloneDeriving #-} 
{-# LANGUAGE GeneralizedNewtypeDeriving #-} 
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE UndecidableInstances #-} -- Only needed for the Show instance for Tree.
module ADS where --(ADS(..), AuthM, Auth, Digestible(..), Authenticated(..), MapAuth(..), shallowAuth) where
import Control.Monad.State
import Control.Monad.Writer

-- For example
import qualified Crypto.Hash as Crypto
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as CBS

-- Only used at the type level, could be replaced with nullary types.
data ADS = Prover | Verifier

-- Abstract
data family AuthM (a :: ADS) s t :: *
-- TODO: Use a better Monoid.
newtype instance AuthM 'Prover s t = Output { runOutput :: Writer [s] t }
    deriving (Functor, Applicative, Monad, MonadWriter [s])
newtype instance AuthM 'Verifier s t = Input { runInput :: StateT [s] Maybe t }
    deriving (Functor, Applicative, Monad, MonadState [s])
            
-- Abstract
data family Auth (t :: *) (a :: ADS)
data instance Auth t 'Prover = WithDigest {-# UNPACK #-} !t {-# UNPACK #-} !(Digest t)
newtype instance Auth t 'Verifier = OnlyDigest (Digest t)

instance (Show t, Show (Digest t)) => Show (Auth t 'Prover) where
    showsPrec n (WithDigest t d) = showParen (n > 0) $ ("WithDigest "++) . showsPrec 11 t . (' ':) . showsPrec 11 d

instance (Show (Digest t)) => Show (Auth t 'Verifier) where
    showsPrec n (OnlyDigest d) = showParen (n > 0) $ ("OnlyDigest "++) . showsPrec 11 d

class (Eq (Digest t)) => Digestible t where
    type Digest t :: *
    digest :: t -> Digest t

-- Are these instances right?
instance (Eq (Digest t), Authenticated a) => Digestible (Auth t a) where    
    type Digest (Auth t a) = Digest t
    digest a = getDigest a

class Authenticated (a :: ADS) where
    type AuthResult a s t :: *
    auth :: Digestible t => t -> Auth t a
    unauth :: Digestible t => Auth t a -> AuthM a t t
    getDigest :: Auth t a -> Digest t
    runAuthM :: AuthM a s t -> AuthResult a s t

instance Authenticated 'Prover where
    type AuthResult 'Prover s t = (t, [s])
    auth t = WithDigest t (digest t)
    unauth (WithDigest t _) = tell [t] >> return t
    getDigest (WithDigest _ d) = d
    runAuthM (Output m) = runWriter m

instance Authenticated 'Verifier where
    type AuthResult 'Verifier s t = [s] -> Maybe t
    auth t = OnlyDigest (digest t)
    unauth (OnlyDigest d) = do
        ts <- get
        case ts of
            [] -> fail "Unexpected end of proof stream"
            (t:ts') -> do
                put ts'
                if digest t == d then return t else fail "Digest verification failed"
    getDigest (OnlyDigest d) = d
    runAuthM (Input m) = fmap fst . runStateT m

runProver :: AuthM 'Prover s t -> AuthResult 'Prover s t
runProver = runAuthM

runVerifier :: AuthM 'Verifier s t -> AuthResult 'Verifier s t
runVerifier = runAuthM

class MapAuth (f :: ADS -> *) where
    mapAuth :: f 'Prover -> f 'Verifier

instance MapAuth (Auth t) where
    mapAuth (WithDigest _ d) = OnlyDigest d

shallowAuth :: (Digest s ~ Digest t) => Auth s 'Prover -> Auth t 'Verifier
shallowAuth (WithDigest _ d) = OnlyDigest d

-- Example

-- Merkle Tree
data Bit = L | R
data Tree a = Tip String | Bin (Auth (Tree a) a) (Auth (Tree a) a)
deriving instance (Show (Auth (Tree a) a)) => Show (Tree a)

instance (Digestible (Auth (Tree a) a)) => Digestible (Tree a) where
    type Digest (Tree a) = Crypto.Digest Crypto.SHA256
    digest (Tip s) = Crypto.hash (CBS.pack s)
    digest (Bin l r) = Crypto.hashFinalize (Crypto.hashUpdate (Crypto.hashUpdate Crypto.hashInit (digest l)) (digest r))

instance MapAuth Tree where
    mapAuth (Tip s) = Tip s
    mapAuth (Bin l r) = Bin (shallowAuth l) (shallowAuth r)

-- For simplicity, assumes a complete tree.
fetch :: (Authenticated a, Monad (AuthM a (Tree a))) => [Bit] -> Auth (Tree a) a -> AuthM a (Tree a) String 
fetch ix t = do
    t' <- unauth t
    case (ix, t') of
        ([]   , Tip s) -> return s
        (L:ix', Bin l _) -> fetch ix' l
        (R:ix', Bin _ r) -> fetch ix' r

exampleTree :: (Authenticated a) => Auth (Tree a) a
exampleTree = auth (Bin (auth (Tip "left")) (auth (Tip "right")))
