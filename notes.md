* Make AuthM a Pipe or Conduit or at least behave similar to one so proof streams can be sent and received incrementally.
* Implement SYB.
* Implement Template Haskell based derivation of MapAuth.
* Add generic implementation of Digestible.
* Add more examples from paper.
* Make demo client/server executable.
* Optimize AuthM monads 
    * inline and choose a better Monoid for the Prover (or even better use a Pipe/Conduit based approach)
    * inline and switch the StateT Maybe monad to a CPS based version
* Try to make the types a little nicer (i.e. so Show is derivable and FlexibleContexts and UndecidableInstances aren't needed by the user)
* Maybe make AuthM monad transformers.  (This is trivial to do, it's just a question on how this impacts the semantics.  I don't think it would impact security but I'm not sure about this.  It definitely impacts coherence (e.g. the Skip List example from the paper.))
* Maybe support Cloud Haskell functions...
* Explore accomplishing higher level optimization in a clean manner (or give up and implement the ones from the paper as-is)
