{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE TypeFamilies #-}
module Data.Authenticated.Fix (FixAuth(..)) where
import Data.Authenticated

newtype FixAuth f a = FixAuth { unFixAuth :: f (Auth (FixAuth f a) a) }

instance (Show (f (Auth (FixAuth f a) a))) => Show (FixAuth f a) where
    showsPrec n (FixAuth f) = showsPrec n f

instance (Digest (FixAuth f Prover) ~ Digest (FixAuth f Verifier), Functor f) => MapAuth (FixAuth f) where
    mapAuth (FixAuth f) = FixAuth (fmap shallowAuth f)

-- Requires UndecidableInstances
instance (Authenticated a, Digestible (f (Auth (FixAuth f a) a))) => Digestible (FixAuth f a) where
    type Digest (FixAuth f a) = Digest (f (Auth (FixAuth f a) a))
    digest (FixAuth f) = digest f
