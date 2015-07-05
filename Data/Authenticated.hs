{-# LANGUAGE EmptyDataDecls #-} 
{-# LANGUAGE GeneralizedNewtypeDeriving #-} 
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DefaultSignatures #-}
module Data.Authenticated (Prover, Verifier, AuthM, Auth, runProver, runVerifier, Digestible(..), Authenticated(..), GMapAuth(..), MapAuth(..), shallowAuth) where
-- Implements the ideas from "Authenticated Data Structures, Generically" by Andrew Miller, Michael Hicks, Jonathan Katz, and Elaine Shi.
import Control.Monad.State
import Control.Monad.Writer
import GHC.Generics (Generic1, to1, from1, Rep1)

data Prover
data Verifier

class GMapAuth f where    
    gmapAuth :: f Prover -> f Verifier

-- Abstract
data family AuthM a s t
-- TODO: Use a better Monoid.
newtype instance AuthM Prover s t = Output { runOutput :: Writer [s] t }
    deriving (Functor, Applicative, Monad, MonadWriter [s])
newtype instance AuthM Verifier s t = Input { runInput :: StateT [s] Maybe t }
    deriving (Functor, Applicative, Monad, MonadState [s])
            
-- Abstract
data family Auth t a
data instance Auth t Prover = WithDigest !t !(Digest t)
newtype instance Auth t Verifier = OnlyDigest (Digest t)

instance (Show t, Show (Digest t)) => Show (Auth t Prover) where
    showsPrec n (WithDigest t d) = showParen (n > 0) $ ("WithDigest "++) . showsPrec 11 t . (' ':) . showsPrec 11 d

instance (Show (Digest t)) => Show (Auth t Verifier) where
    showsPrec n (OnlyDigest d) = showParen (n > 0) $ ("OnlyDigest "++) . showsPrec 11 d

class (Eq (Digest t)) => Digestible t where
    type Digest t :: *
    digest :: t -> Digest t

-- Is this instance right?
instance (Eq (Digest t), Authenticated a) => Digestible (Auth t a) where    
    type Digest (Auth t a) = Digest t
    digest a = getDigest a

class Authenticated a where
    type AuthResult a s t :: *
    auth :: Digestible t => t -> Auth t a
    unauth :: Digestible t => Auth t a -> AuthM a t t
    getDigest :: Auth t a -> Digest t
    runAuthM :: AuthM a s t -> AuthResult a s t

instance Authenticated Prover where
    type AuthResult Prover s t = (t, [s])
    auth t = WithDigest t (digest t)
    unauth (WithDigest t _) = tell [t] >> return t
    getDigest (WithDigest _ d) = d
    runAuthM (Output m) = runWriter m

instance Authenticated Verifier where
    type AuthResult Verifier s t = [s] -> Maybe t
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

runProver :: AuthM Prover s t -> AuthResult Prover s t
runProver = runAuthM

runVerifier :: AuthM Verifier s t -> AuthResult Verifier s t
runVerifier = runAuthM

class MapAuth f where
    mapAuth :: f Prover -> f Verifier
    default mapAuth :: (GMapAuth (Rep1 f), Generic1 f) => f Prover -> f Verifier
    mapAuth = to1 . gmapAuth . from1

instance MapAuth (Auth t) where
    mapAuth = shallowAuth

shallowAuth :: (Digest s ~ Digest t) => Auth s Prover -> Auth t Verifier
shallowAuth (WithDigest _ d) = OnlyDigest d
