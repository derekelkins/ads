{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
module Data.Authenticated.Generic (Auth1(..)) where
import Data.Authenticated
import GHC.Generics

newtype Auth1 f a = Auth1 { getAuth1 :: Auth (f a) a }
-- These two instances are what requires UndecidableInstances.
instance (Show (f Prover), Show (Digest (f Prover))) => Show (Auth1 f Prover) where
    showsPrec n = showsPrec n . getAuth1
instance (Show (f Verifier), Show (Digest (f Verifier))) => Show (Auth1 f Verifier) where
    showsPrec n = showsPrec n . getAuth1

instance GMapAuth V1 where
    gmapAuth = undefined

instance GMapAuth U1 where
    gmapAuth U1 = U1

instance (GMapAuth l, GMapAuth r) => GMapAuth (l :+: r) where
    gmapAuth (L1 x) = L1 (gmapAuth x)
    gmapAuth (R1 x) = R1 (gmapAuth x)

instance (GMapAuth l, GMapAuth r) => GMapAuth (l :*: r) where
    gmapAuth (x :*: y) = gmapAuth x :*: gmapAuth y

instance GMapAuth (K1 i c) where
    gmapAuth (K1 c) = K1 c

instance (GMapAuth f) => GMapAuth (M1 i t f) where
    gmapAuth (M1 x) = M1 (gmapAuth x)

instance (MapAuth f) => GMapAuth (Rec1 f) where
    gmapAuth (Rec1 x) = Rec1 (mapAuth x)

-- instance GMapAuth Par1 - This should never happen for correct data types (i.e. whose parameter is Authenticated)

instance (Digest (f Prover) ~ Digest (f Verifier)) => MapAuth (Auth1 f) where
    mapAuth (Auth1 x) = Auth1 (shallowAuth x)
