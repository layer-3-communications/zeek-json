{-# language BangPatterns #-}
{-# language MagicHash #-}

import Data.ByteString.Internal (ByteString(PS))
import Data.Primitive (ByteArray(..))
import GHC.Exts (Int(I#),byteArrayContents#,unsafeCoerce#)
import GHC.Exts (sizeofByteArray#)
import GHC.ForeignPtr (ForeignPtr(ForeignPtr),ForeignPtrContents(PlainPtr))
import Gauge (bgroup,bench,whnf,defaultMain)

import qualified Data.Aeson as AE
import qualified Data.Bytes as Bytes
import qualified Examples as E
import qualified Zeek.Json as Zeek

-- To demonstrate that all the work in this library is not in vain,
-- we benchmark its performance against aeson's performance. The
-- astute observer will notice that this benchmark is unfair to
-- zeek-json. Notably, the benchmarks for zeek-json decode the
-- serialized data all the way to an immidiately usable Haskell
-- data type while those for aeson only decode the serialized data
-- to a JSON syntax tree (aeson's Value type). Despite the unequal
-- work, zeek-json outperforms aeson by a factor of two. On the
-- author's laptop:
--
-- implmentation/Kerberos-A  mean 1.667 μs  ( +- 28.54 ns  )
-- implmentation/Kerberos-B  mean 2.764 μs  ( +- 98.95 ns  )
-- aeson/Kerberos-A          mean 3.560 μs  ( +- 38.52 ns  )
-- aeson/Kerberos-B          mean 6.541 μs  ( +- 123.2 ns  )

main :: IO ()
main = defaultMain
  [ bgroup "structured"
    [ bench "Kerberos-A"
        (whnf (\x -> Zeek.decodeKerberos (Bytes.fromByteArray x)) E.encodedKerberosA)
    , bench "Kerberos-B"
        (whnf (\x -> Zeek.decodeKerberos (Bytes.fromByteArray x)) E.encodedKerberosB)
    ]
  , bgroup "unstructured"
    [ bench "Kerberos-A"
        (whnf (\x -> Zeek.decode (Bytes.fromByteArray x)) E.encodedKerberosA)
    , bench "Kerberos-B"
        (whnf (\x -> Zeek.decode (Bytes.fromByteArray x)) E.encodedKerberosB)
    , bench "DNS-C"
        (whnf (\x -> Zeek.decode (Bytes.fromByteArray x)) E.encodedDnsC)
    ]
  , bgroup "aeson"
    [ bench "Kerberos-A"
        (whnf aesonDecode E.encodedKerberosA)
    , bench "Kerberos-B"
        (whnf aesonDecode E.encodedKerberosB)
    , bench "DNS-C"
        (whnf aesonDecode E.encodedDnsC)
    ]
  ]

aesonDecode :: ByteArray -> Maybe AE.Value
aesonDecode !x = AE.decodeStrict' (fromPinned x)

-- Convert a pinned immutable byte array to a bytestring.
fromPinned :: ByteArray -> ByteString
{-# inline fromPinned #-}
fromPinned (ByteArray arr# ) = PS
  (ForeignPtr (byteArrayContents# arr# ) (PlainPtr (unsafeCoerce# arr#)))
  0 (I# (sizeofByteArray# arr# ))
  
