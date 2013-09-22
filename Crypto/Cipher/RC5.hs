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
-- It even includes support for non-standard (not recommended) 16bit blocks.
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

-- | RC5 encryption
--
-- Using the given blocksize, number of rounds and key, encrypts the plaintext.
--
-- * Valid blocksizes are 16, 32, 64, 128
--
-- * Valid rounds are 0 - 256
--
-- If in doubt, 32bit blocks and 12 rounds is the most common combination
--
-- >encrypt 32 12 [1,2,3,4] [0xFE,0x13,0x37,0x00]
-- 
-- Encrypts the plaintext (last) with a blocksize of 32 bits, 12 rounds and key @[1,2,3,4]@
-- 
-- Maximum key length is 256. A common (and sufficient) length is 16 bytes.
-- The length of the result is divisible by the block size (i.e. 2, 4, 8, 16)
-- On invalid input, the empty list is returned.

encrypt :: Int -> Int -> [Word8] -> [Word8] -> [Word8]
encrypt blocksize rounds key plain
  | length key > 256 || null key || null plain || rounds > 256 || rounds < 0 = []
  | blocksize == 16 = crypt8 encryptblock8 key rounds plain
  | blocksize == 32 = crypt16 encryptblock16 key rounds plain
  | blocksize == 64 = crypt32 encryptblock32 key rounds plain
  | blocksize == 128 = crypt64 encryptblock64 key rounds plain
  | otherwise = []

-- | RC5 decryption
--
-- All parameters must match those used for encryption
-- The length of the result is equal to the length of the input

decrypt :: Int -> Int -> [Word8] -> [Word8] -> [Word8]
decrypt blocksize rounds key cipher
  | length key > 256 || null key || null cipher || rounds > 256 || rounds < 0 = []
  | blocksize == 16 = crypt8 decryptblock8 key rounds cipher
  | blocksize == 32 = crypt16 decryptblock16 key rounds cipher
  | blocksize == 64 = crypt32 decryptblock32 key rounds cipher
  | blocksize == 128 = crypt64 decryptblock64 key rounds cipher
  | otherwise = []

--Blocksize 16bit/2B, wordsize Word8
ws8_w  = 8   :: Int  -- W
ws8_ww = 1   :: Int  -- w/8

--Blocksize 32bit/4B, wordsize Word16
ws16_w  = 16 :: Int -- W
ws16_ww = 2  :: Int  -- w/8

--Blocksize 64bit/8B, wordsize Word32
ws32_w  = 32 :: Int -- W
ws32_ww = 4  :: Int  -- w/8

--Blocksize 128bit/16B, wordsize Word64
ws64_w  = 64 :: Int -- W
ws64_ww = 8  :: Int  -- w/8

-- Magic constants
-- (they are easily calculated from euler's number and the golden ratio)
p8 = 0xb7 :: Word8
q8 = 0x9f :: Word8
p16 = 0xb7e1 :: Word16
q16 = 0x9e37 :: Word16
p32 = 0xb7e15163 :: Word32
q32 = 0x9e3779b9 :: Word32
p64 = 0xb7e151628aed2a6b :: Word64
q64 = 0x9e3779b97f4a7c15 :: Word64

-- Examples for RC5/32/12/16
key1 = take 16 $ repeat 0 :: [Word8]
key2 = [0x91,0x5F,0x46,0x19,0xBE,0x41,0xB2,0x51,0x63,0x55,0xA5,0x01,0x10,0xA9,0xCE,0x91] :: [Word8]
plain1 = take 8 $ repeat 0 :: [Word8]
plain2 = [0x21,0xA5,0xDB,0xEE,0x15,0x4B,0x8F,0x6D] :: [Word8]
plain2' = (0xEEDBA521,0x6D8F4B15) :: (Word32,Word32)

-- Left rotate for encryption
rotl :: Bits a => a -> Int -> Int -> a
rotl x s w = (shiftL x (s .&. (w-1))) .|. (shiftR x (w-(s .&. (w-1))))

-- Right rotate for decryption
rotr :: Bits a => a -> Int -> Int -> a
rotr x s w = (shiftR x (s .&. (w-1))) .|. (shiftL x (w-(s .&. (w-1))))

crypt8 :: ([Word8] -> Int -> (Word8,Word8) -> [Word8]) -> [Word8] -> Int -> [Word8] -> [Word8]
crypt8 operation key rounds plain =
  concatMap (operation s rounds) ab
  where ab = splitAB8 plain
        s = keyexpand8 key rounds

crypt16 :: ([Word16] -> Int -> (Word16,Word16) -> [Word8]) -> [Word8] -> Int -> [Word8] -> [Word8]
crypt16 operation key rounds content =
  concatMap (operation s rounds) ab
  where ab = splitAB16 content
        s = keyexpand16 key rounds

crypt32 :: ([Word32] -> Int -> (Word32,Word32) -> [Word8]) -> [Word8] -> Int -> [Word8] -> [Word8]
crypt32 operation key rounds content =
  concatMap (operation s rounds) ab
  where ab = splitAB32 content
        s = keyexpand32 key rounds

crypt64 :: ([Word64] -> Int -> (Word64,Word64) -> [Word8]) -> [Word8] -> Int -> [Word8] -> [Word8]
crypt64 operation key rounds content =
  concatMap (operation s rounds) ab
  where ab = splitAB64 content
        s = keyexpand64 key rounds


encryptblock8 :: [Word8] -> Int -> (Word8,Word8) -> [Word8]
encryptblock8 s rounds (a,b) =
  [a',b']
  where (a',b') = enc8 rounds 1 (a + (s!!0)) (b + (s!!1)) s
        
encryptblock16 :: [Word16] -> Int -> (Word16,Word16) -> [Word8]
encryptblock16 s rounds (a,b) =
  word2bytes 2 a' ++ word2bytes 2 b'
  where (a',b') = enc16 rounds 1 (a + (s!!0)) (b + (s!!1)) s

encryptblock32 :: [Word32] -> Int -> (Word32,Word32) -> [Word8]
encryptblock32 s rounds (a,b) =
  word2bytes 4 a' ++ word2bytes 4 b'
  where (a',b') = enc32 rounds 1 (a + (s!!0)) (b + (s!!1)) s

encryptblock32' :: [Word32] -> Int -> (Word32,Word32) -> (Word32,Word32)
encryptblock32' s rounds (a,b) = (a',b')
  where (a',b') = enc32 rounds 1 (a + (s!!0)) (b + (s!!1)) s

encryptblock64 :: [Word64] -> Int -> (Word64,Word64) -> [Word8]
encryptblock64 s rounds (a,b) =
  word2bytes 8 a' ++ word2bytes 8 b'
  where (a',b') = enc64 rounds 1 (a + (s!!0)) (b + (s!!1)) s

decryptblock8 :: [Word8] -> Int -> (Word8,Word8) -> [Word8]
decryptblock8 s rounds (a,b) =
  (a' - s!!0) : [(b' - s!!1)]
  where (a',b') = dec8 rounds a b s
  
decryptblock16 :: [Word16] -> Int -> (Word16,Word16) -> [Word8]
decryptblock16 s rounds (a,b) =
  word2bytes 2 (a' - s!!0) ++ word2bytes 2 (b' - s!!1)
  where (a',b') = dec16 rounds a b s
  
decryptblock32 :: [Word32] -> Int -> (Word32,Word32) -> [Word8]
decryptblock32 s rounds (a,b) =
  word2bytes 4 (a' - s!!0) ++ word2bytes 4 (b' - s!!1)
  where (a',b') = dec32 rounds a b s

decryptblock32' :: [Word32] -> Int -> (Word32,Word32) -> (Word32,Word32)
decryptblock32' s rounds (a,b) = ((a' - s!!0) , (b' - s!!1))
  where (a',b') = dec32 rounds a b s

decryptblock64 :: [Word64] -> Int -> (Word64,Word64) -> [Word8]
decryptblock64 s rounds (a,b) =
  word2bytes 8 (a' - s!!0) ++ word2bytes 8 (b' - s!!1)
  where (a',b') = dec64 rounds a b s
  
enc8 :: Int -> Int -> Word8 -> Word8 -> [Word8] -> (Word8,Word8)
enc8 rounds i a b s
  | i > rounds = (a,b)
  | otherwise = enc8 rounds (i+1) a' b' s
  where a' = (rotl (a `xor` b)  (fromIntegral b)  ws8_w) + (s !! (2*i))
        b' = (rotl (b `xor` a') (fromIntegral a') ws8_w) + (s !! (2*i+1))  
  
enc16 :: Int -> Int -> Word16 -> Word16 -> [Word16] -> (Word16,Word16)
enc16 rounds i a b s
  | i > rounds = (a,b)
  | otherwise = enc16 rounds (i+1) a' b' s
  where a' = (rotl (a `xor` b)  (fromIntegral b)  ws16_w) + (s !! (2*i))
        b' = (rotl (b `xor` a') (fromIntegral a') ws16_w) + (s !! (2*i+1))
  
enc32 :: Int -> Int -> Word32 -> Word32 -> [Word32] -> (Word32,Word32)
enc32 rounds i a b s
  | i > rounds = (a,b)
  | otherwise = enc32 rounds (i+1) a' b' s
  where a' = (rotl (a `xor` b)  (fromIntegral b)  ws32_w ) + (s !! (2*i))
        b' = (rotl (b `xor` a') (fromIntegral a') ws32_w ) + (s !! (2*i+1))

enc64 :: Int -> Int -> Word64 -> Word64 -> [Word64] -> (Word64,Word64)
enc64 rounds i a b s
  | i > rounds = (a,b)
  | otherwise = enc64 rounds (i+1) a' b' s
  where a' = (rotl (a `xor` b)  (fromIntegral b)  ws64_w ) + (s !! (2*i))
        b' = (rotl (b `xor` a') (fromIntegral a') ws64_w ) + (s !! (2*i+1))

dec8 :: Int -> Word8 -> Word8 -> [Word8] -> (Word8,Word8)
dec8 i a b s
  | i == 0 = (a,b)
  | otherwise = dec8 (i-1) a' b' s
  where b' = (rotr (b - (s !! (2*i+1))) (fromIntegral a)  ws8_w) `xor` a
        a' = (rotr (a - (s !! (2*i)))   (fromIntegral b') ws8_w) `xor` b'
        
dec16 :: Int -> Word16 -> Word16 -> [Word16] -> (Word16,Word16)
dec16 i a b s
  | i == 0 = (a,b)
  | otherwise = dec16 (i-1) a' b' s
  where b' = (rotr (b - (s !! (2*i+1))) (fromIntegral a)  ws16_w) `xor` a
        a' = (rotr (a - (s !! (2*i)))   (fromIntegral b') ws16_w) `xor` b'

dec32 :: Int -> Word32 -> Word32 -> [Word32] -> (Word32,Word32)
dec32 i a b s
  | i == 0 = (a,b)
  | otherwise = dec32 (i-1) a' b' s
  where b' = (rotr (b - (s !! (2*i+1))) (fromIntegral a)  ws32_w ) `xor` a
        a' = (rotr (a - (s !! (2*i)))   (fromIntegral b') ws32_w ) `xor` b'

dec64 :: Int -> Word64 -> Word64 -> [Word64] -> (Word64,Word64)
dec64 i a b s
  | i == 0 = (a,b)
  | otherwise = dec64 (i-1) a' b' s
  where b' = (rotr (b - (s !! (2*i+1))) (fromIntegral a)  ws64_w ) `xor` a
        a' = (rotr (a - (s !! (2*i)))   (fromIntegral b') ws64_w ) `xor` b'

splitAB8 :: [Word8] -> [(Word8,Word8)]
splitAB8 plain = map pair ab8'
  where ab8' = chunksOf 2 plain

splitAB16 :: [Word8] -> [(Word16,Word16)]
splitAB16 plain = map pair ab16'
  where chunks = chunksOf ws16_ww plain
        ab16 = map bytes2word chunks
        ab16' = chunksOf 2 ab16

splitAB32 :: [Word8] -> [(Word32,Word32)]
splitAB32 plain = map pair ab32'
  where chunks = chunksOf ws32_ww plain
        ab32 = map bytes2word chunks
        ab32' = chunksOf 2 ab32
        
splitAB64 :: [Word8] -> [(Word64,Word64)]
splitAB64 plain = map pair ab64'
  where chunks = chunksOf ws64_ww plain
        ab64 = map bytes2word chunks
        ab64' = chunksOf 2 ab64

pair :: Integral a => [a] -> (a,a)
pair (a:b:_) = (a,b)
pair (a:[]) = (a,0)


-- KEY INIT & EXPANSION
keyexpand8 :: [Word8] -> Int -> [Word8]
keyexpand8 key rounds =
  mixsecretkey ws8_w s l -- mix in secret key
  where l = key  -- convert key to words
        s = makeS (2*rounds+2) p8 q8 -- init S table

keyexpand16 :: [Word8] -> Int -> [Word16]
keyexpand16 key rounds = 
  mixsecretkey ws16_w s l -- mix in secret key
  where l = makewordkey16 key  -- convert key to words
        s = makeS (2*rounds+2) p16 q16 -- init S table

keyexpand32 :: [Word8] -> Int -> [Word32]
keyexpand32 key rounds = 
  mixsecretkey ws32_w s l -- mix in secret key
  where l = makewordkey32 key  -- convert key to words
        s = makeS (2*rounds+2) p32 q32 -- init S table

keyexpand64 :: [Word8] -> Int -> [Word64]
keyexpand64 key rounds = 
  mixsecretkey ws64_w s l -- mix in secret key
  where l = makewordkey64 key  -- convert key to words
        s = makeS (2*rounds+2) p64 q64 -- init S table

mixsecretkey :: (Bits a, Integral a) => Int -> [a] -> [a] -> [a]
mixsecretkey bs s l = s'
  where k = if ll > t then 3 * ll else 3 * t
        ll = length l
        t = length s
        (s',l') = mixS bs k 0 0 0 0 s l t ll

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

makeS :: Integral a => Int -> a -> a -> [a]
makeS t seed const
  | t == 0 = []
  | otherwise = seed : makeS (t-1) (seed + const) const

{--  
makewordkey8 :: [Word8] -> [Word8]
makewordkey8 key = map sum chunks
  where expokey = map (\(k,m) -> shiftL (fromIntegral k) m) (zip key (repeat 0))
        chunks = chunksOf ws8_ww expokey
--}

makewordkey16 :: [Word8] -> [Word16]
makewordkey16 key = map sum chunks
  where expokey = map (\(k,m) -> shiftL (fromIntegral k) m) (zip key (cycle [0,8]))
        chunks = chunksOf ws16_ww expokey

makewordkey32 :: [Word8] -> [Word32]
makewordkey32 key = map sum chunks
  where expokey = map (\(k,m) -> shiftL (fromIntegral k) m) (zip key (cycle [0,8,16,24]))
        chunks = chunksOf ws32_ww expokey

makewordkey64 :: [Word8] -> [Word64]
makewordkey64 key = map sum chunks
  where expokey = map (\(k,m) -> shiftL (fromIntegral k) m) (zip key (cycle [0,8,16,24,32,40,48,56]))
        chunks = chunksOf ws64_ww expokey

bytes2word :: (Bits a, Integral a) => [Word8] -> a
bytes2word bs = bytes2word' 0 (fromIntegral 0) bs

bytes2word' :: (Bits a, Integral a) => Int -> a -> [Word8] -> a
bytes2word' shft sofar [] = sofar
bytes2word' shft sofar (x:xs) = bytes2word' (shft+8) (sofar + shiftL (fromIntegral x) shft) xs

word2bytes :: (Bits a, Integral a) => Int -> a -> [Word8]
word2bytes ws w
  | ws == 0 = []
  | otherwise = (fromIntegral (w .&. 0xFF)) : (word2bytes (ws-1) (shiftR w 8))
