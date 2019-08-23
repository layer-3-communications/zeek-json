{-# language BangPatterns #-}
{-# language ScopedTypeVariables #-}
{-# language TypeApplications #-}
{-# language OverloadedStrings #-}
{-# language DerivingStrategies #-}
{-# language StandaloneDeriving #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

import Test.Tasty (defaultMain,testGroup,TestTree)
import Test.Tasty.HUnit ((@=?),assertFailure)

import qualified Data.Json.Tokenize as J
import qualified Examples as E
import qualified Data.Bytes as Bytes
import qualified Zeek.Json as Zeek
import qualified Test.Tasty.HUnit as THU

main :: IO ()
main = defaultMain tests

deriving stock instance Eq Zeek.Kerberos
deriving stock instance Show Zeek.Kerberos
deriving stock instance Eq Zeek.TextField
deriving stock instance Show Zeek.TextField
deriving stock instance Eq Zeek.UidField
deriving stock instance Show Zeek.UidField
deriving stock instance Eq Zeek.BoolField
deriving stock instance Show Zeek.BoolField
deriving stock instance Eq Zeek.TimeField
deriving stock instance Show Zeek.TimeField
deriving stock instance Eq Zeek.IpField
deriving stock instance Show Zeek.IpField
deriving stock instance Eq Zeek.PortField
deriving stock instance Show Zeek.PortField
deriving stock instance Eq Zeek.Attribute
deriving stock instance Show Zeek.Attribute

tests :: TestTree
tests = testGroup "Tests"
  [ testGroup "decode"
    [ THU.testCase "A" $
        Right E.kerberosAttrsA
        @=?
        Zeek.decode (Bytes.fromByteArray E.encodedKerberosA)
    , THU.testCase "B" $
        Right E.kerberosAttrsB
        @=?
        Zeek.decode (Bytes.fromByteArray E.encodedKerberosB)
    ]
  , testGroup "decodeKerberos"
    [ THU.testCase "A" $
        case Zeek.decodeKerberos (Bytes.fromByteArray E.encodedKerberosA) of
          Left err -> case J.decode (Bytes.fromByteArray E.encodedKerberosA) of
            Left err' -> assertFailure (show err')
            Right tokens -> assertFailure ("Tokens: " ++ show tokens ++ "\nError: " ++ show err)
          Right a -> E.kerberosA @=? a
    , THU.testCase "B" $
        case Zeek.decodeKerberos (Bytes.fromByteArray E.encodedKerberosB) of
          Left err -> case J.decode (Bytes.fromByteArray E.encodedKerberosB) of
            Left err' -> assertFailure (show err')
            Right tokens -> assertFailure ("Tokens: " ++ show tokens ++ "\nError: " ++ show err)
          Right a -> E.kerberosB @=? a
    ]
  ]
