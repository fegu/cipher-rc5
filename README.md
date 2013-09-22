cipher-rc5
==========

Haskell implementation of RC5
This implementation supports all the standard block lengths of 32, 64 & 128 bits.
It even includes support for non-standard (not recommended) 16bit blocks.

In addition to being useful when required for e.g. legacy integration, this cipher's option of short block lengths makes it useful for encrypting small data such as database primary keys before display.
