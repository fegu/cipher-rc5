-- |
-- Module      : Crypto.Cipher.RC5
-- License     : BSD-style
-- Maintainer  : Finn Espen Gundersen <finn@gundersen.net>
-- Stability   : stable
-- Portability : Good
--
-- Pure implementation of the RC5 variable size block cipher.
-- <http://en.wikipedia.org/wiki/RC5>
--
-- You need to select a block size and number of rounds.
-- If you are unsure, the most common settings are 64bit blocks with 12 rounds.
--
-- This implementation supports all the standard block lengths of 32, 64 & 128 bits.
-- It also includes support for non-standard (not recommended) 16bit blocks.
--
-- In addition to being useful when required for e.g. legacy integration,
-- this cipher's option of short block lengths makes it useful for encrypting 
-- small data such as database primary keys before display.
--
-- Introduced in 1994, RC5 has withstood the tests of time remarkably well.
--

module Crypto.Cipher.RC5 (encrypt,decrypt) where

import Data.Word
import Data.Bits
import Data.List.Split (chunksOf)

----------------------------------------------------------------------------

-- | RC5 Cipher
--
-- Using the given blocksize, number of rounds and key, encrypts the plaintext.
--
-- * Valid blocksizes are 16 (not standard), 32, 64, 128
--
-- * Valid rounds are 0 - 256
--
-- If in doubt, 64bit blocks and 12 rounds is the most common combination.
-- This is called RC5-32/12 (32 is the word size, which is half the block size).
-- 128bit blocks and 18 rounds is also quite common. This is called RC5-64/18
--
-- >encrypt 64 12 [1,2,3,4] [0xFE,0x13,0x37,0x00]
-- 
-- Encrypts the plaintext @[0xFE,0x13,0x37,0x00]@ with a blocksize of 64 bits, 12 rounds and key @[1,2,3,4]@
-- 
-- Maximum key length is 256. A common (and sufficient) length is 16 bytes.
-- The length of the result is divisible by the block size (i.e. 2, 4, 8, 16)
-- On invalid input, the empty list is returned.

encrypt :: Int      -- ^ Blocksize in bits (16, 32, 64 or 128)
        -> Int      -- ^ Number of rounds (0 - 256)
        -> [Word8]  -- ^ Key (max length 256)
        -> [Word8]  -- ^ Plaintext
        -> [Word8]  -- ^ Ciphertext
encrypt blocksize rounds key plain
  | null key || null plain || length (take 257 key) == 257 || rounds > 256 || rounds < 0 = []
  | blocksize ==  16 = crypt ws p8  q8  encryptblock rounds key plain
  | blocksize ==  32 = crypt ws p16 q16 encryptblock rounds key plain
  | blocksize ==  64 = crypt ws p32 q32 encryptblock rounds key plain
  | blocksize == 128 = crypt ws p64 q64 encryptblock rounds key plain
  | otherwise = []
  where ws = shiftR blocksize 4

-- | RC5 decryption
--
-- All parameters must match those used for encryption
-- The length of the result is equal to the length of the input

decrypt :: Int        -- ^ Blocksize in bits
           -> Int     -- ^ Number of rounds
           -> [Word8] -- ^ Key
           -> [Word8] -- ^ Ciphertext
           -> [Word8] -- ^ Recovered plaintext
decrypt blocksize rounds key cipher
  | length key > 256 || null key || null cipher || rounds > 256 || rounds < 0 = []
  | blocksize ==  16 = crypt ws p8  q8  decryptblock rounds key cipher
  | blocksize ==  32 = crypt ws p16 q16 decryptblock rounds key cipher
  | blocksize ==  64 = crypt ws p32 q32 decryptblock rounds key cipher
  | blocksize == 128 = crypt ws p64 q64 decryptblock rounds key cipher
  | otherwise = []
  where ws = shiftR blocksize 4

-- Magic constants
p8  = 0xb7 :: Word8                   -- Two constants, Pw and Qw, are defined for 
q8  = 0x9f :: Word8                   -- any word size W by the expressions:
p16 = 0xb7e1 :: Word16                -- Pw = odd $ ((exp 1) - 2) * (2 ** W)
q16 = 0x9e37 :: Word16                -- Qw = odd $ ((1+sqrt 5)/2-1)* (2**W)
p32 = 0xb7e15163 :: Word32            -- odd(x) adds one if x is even.
q32 = 0x9e3779b9 :: Word32            -- Note that the magic is all dependent on
p64 = 0xb7e151628aed2a6b :: Word64    -- euler's number and the golden ratio.
q64 = 0x9e3779b97f4a7c15 :: Word64    -- No real magic going on here.

-- Example & selftest for RC5/32/12/16. From the appendix of the Rivest reference paper
key1 = take 16 $ repeat 0 :: [Word8]
key2 = [0x91,0x5F,0x46,0x19,0xBE,0x41,0xB2,0x51,0x63,0x55,0xA5,0x01,0x10,0xA9,0xCE,0x91] :: [Word8]
plain1 = take 8 $ repeat 0 :: [Word8]
cipher1 = [0x21,0xA5,0xDB,0xEE,0x15,0x4B,0x8F,0x6D] :: [Word8]
cipher1' = (0xEEDBA521,0x6D8F4B15) :: (Word32,Word32)

selftestresults = [[33,165,219,238,21,75,143,109]
                  ,[247,192,19,172,91,43,137,82]
                  ,[47,66,179,183,3,105,252,146]
                  ,[101,193,120,178,132,209,151,204]
                  ,[235,68,228,21,218,49,152,36]]

selftest = selftest' key1 plain1 selftestresults

selftest' key plain fasit
  | null fasit = []
  | otherwise = [((decrypt 64 12 key cipher) == plain) && (cipher == (head fasit))] ++ selftest' (nextkey cipher) cipher (tail fasit)
  where cipher = encrypt 64 12 key plain
        nextkey cipher = map (\j -> fromIntegral (((bytes2word (take 4 cipher))::Word32) `mod` (255-j))) [0..15]

-- Left rotate for encryption
rotl :: Bits a => a -> Int -> Int -> a
rotl x s w = (shiftL x (s .&. (w-1))) .|. (shiftR x (w-(s .&. (w-1))))

-- Right rotate for decryption
rotr :: Bits a => a -> Int -> Int -> a
rotr x s w = (shiftR x (s .&. (w-1))) .|. (shiftL x (w-(s .&. (w-1))))

crypt :: (Bits a, Integral a) => Int -> a -> a -> (Int -> [a] -> Int -> (a,a) -> [Word8]) -> Int -> [Word8] -> [Word8] -> [Word8]
crypt ws p q operation rounds key content =
  concatMap (operation ws s rounds) ab
  where ab = splitAB ws content
        s = keyexpand ws p q key rounds

encryptblock :: (Bits a, Integral a) => Int -> [a] -> Int -> (a,a) -> [Word8]
encryptblock ws s rounds (a,b) =
  word2bytes ws a' ++ word2bytes ws b'
  where (a',b') = enc (ws*8) rounds 1 (a + (s!!0)) (b + (s!!1)) s
 
decryptblock :: (Bits a, Integral a) => Int -> [a] -> Int -> (a,a) -> [Word8]
decryptblock ws s rounds (a,b) =
  word2bytes ws (a' - s!!0) ++ word2bytes ws (b' - s!!1)
  where (a',b') = dec (ws*8) rounds a b s

enc :: (Bits a, Integral a) => Int -> Int -> Int -> a -> a -> [a] -> (a,a)
enc mask rounds i a b s
  | i > rounds = (a,b)
  | otherwise = enc mask rounds (i+1) a' b' s
  where a' = (rotl (a `xor` b)  (fromIntegral b)  mask) + (s !! (2*i))
        b' = (rotl (b `xor` a') (fromIntegral a') mask) + (s !! (2*i+1))

dec :: (Bits a, Integral a) => Int -> Int -> a -> a -> [a] -> (a,a)
dec mask i a b s
  | i == 0 = (a,b)
  | otherwise = dec mask (i-1) a' b' s
  where b' = (rotr (b - (s !! (2*i+1))) (fromIntegral a)  mask) `xor` a
        a' = (rotr (a - (s !! (2*i)))   (fromIntegral b') mask) `xor` b'

splitAB :: (Bits a, Integral a) => Int -> [Word8] -> [(a,a)]
splitAB ws bs = map pair ab
  where chunks = chunksOf ws bs
        ab = chunksOf 2 (map bytes2word chunks)
        
pair :: Integral a => [a] -> (a,a)
pair (a:b:_) = (a,b)
pair (a:[]) = (a,0)

-- KEY INIT & EXPANSION
keyexpand :: (Bits a, Integral a) => Int -> a -> a -> [Word8] -> Int -> [a]
keyexpand ws p q key rounds = mixsecretkey ws s l -- mix in secret key
  where l = makewordkey ws key  -- convert key to words
        s = makeS (2*rounds+2) p q -- init S table

mixsecretkey :: (Bits a, Integral a) => Int -> [a] -> [a] -> [a]
mixsecretkey bs s l = s'
  where k = if ll > t then 3 * ll else 3 * t
        ll = length l
        t = length s
        (s',l') = mixS (bs*8) k 0 0 0 0 s l t ll

-- Mixes S box with key. Paramter names may look cryptic, but matches those in standard
mixS :: (Bits a, Integral a) => Int -> Int -> a -> a -> Int -> Int -> [a] -> [a] -> Int -> Int -> ([a],[a])
mixS bs k a b i j s l t ll
  | k == 0 = (s,l)
  | otherwise = mixS bs (k-1) a' b' i' j' s' l' t ll
  where a' = rotl ((s !! i) + a + b) 3 bs
        b' = rotl ((l !! j) + a' + b) (fromIntegral (a'+b)) bs
        i' = (i + 1) `mod` t
        j' = (j + 1) `mod` ll
        s' = (take i s) ++ [a'] ++ (drop (i+1) s)
        l' = (take j l) ++ [b'] ++ (drop (j+1) l)

-- Creates S box. Could be precomputed for the most common variants.
makeS :: Integral a => Int -> a -> a -> [a]
makeS t seed const
  | t == 0 = []
  | otherwise = seed : makeS (t-1) (seed + const) const

makewordkey :: (Bits a, Integral a) => Int -> [Word8] -> [a]
makewordkey ws key = map sum chunks
  where expokey = map (\(k,m) -> shiftL (fromIntegral k) m) (zip key (cycle (take ws [0,8..])))
        chunks = chunksOf ws expokey

bytes2word :: (Bits a, Integral a) => [Word8] -> a
bytes2word bs = bytes2word' 0 (fromIntegral 0) bs

bytes2word' :: (Bits a, Integral a) => Int -> a -> [Word8] -> a
bytes2word' shft sofar [] = sofar
bytes2word' shft sofar (x:xs) = bytes2word' (shft+8) (sofar + shiftL (fromIntegral x) shft) xs

word2bytes :: (Bits a, Integral a) => Int -> a -> [Word8]
word2bytes ws w
  | ws == 0 = []
  | otherwise = (fromIntegral (w .&. 0xFF)) : (word2bytes (ws-1) (shiftR w 8))
