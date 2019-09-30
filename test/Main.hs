{-# language BangPatterns #-}
{-# language LambdaCase #-}
{-# language ScopedTypeVariables #-}
{-# language TypeApplications #-}
{-# language OverloadedStrings #-}
{-# language DerivingStrategies #-}
{-# language StandaloneDeriving #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

import Test.Tasty (defaultMain,testGroup,TestTree)
import Test.Tasty.HUnit ((@=?),assertFailure)

import qualified Data.Bytes as Bytes
import qualified Data.List as L
import qualified Examples as E
import qualified GHC.Exts as Exts
import qualified Json.Token as J
import qualified Net.IP as IP
import qualified Test.Tasty.HUnit as THU
import qualified Zeek.Json as Zeek

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
deriving stock instance Eq Zeek.IpsField
deriving stock instance Show Zeek.IpsField
deriving stock instance Eq Zeek.ByteField
deriving stock instance Show Zeek.ByteField
deriving stock instance Eq Zeek.Word16Field
deriving stock instance Show Zeek.Word16Field
deriving stock instance Eq Zeek.Word64sField
deriving stock instance Show Zeek.Word64sField
deriving stock instance Eq Zeek.Attribute
deriving stock instance Show Zeek.Attribute

deriving stock instance Eq Zeek.ZeekException
deriving stock instance Eq Zeek.ZeekParsingException

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
    , THU.testCase "C" $
        case Zeek.decode (Bytes.fromByteArray E.encodedDnsC) of
          Left e -> assertFailure (show e)
          Right r -> case L.find isAnswers r of
            Just (Zeek.IpsAttribute _ ips) -> do
              Exts.fromList
                [ IP.getIP (IP.ipv4 192 0 2 231)
                , IP.getIP (IP.ipv4 192 0 2 232)
                , IP.getIP (IP.ipv4 192 0 2 233)
                , IP.getIP (IP.ipv4 192 0 2 234)
                ] @=? ips
              case L.find isTtls r of
                Just (Zeek.Word64sAttribute _ ttls) -> do
                  Exts.fromList [3600,7200,300,1200] @=? ttls
                _ -> assertFailure "missing TTLs field"
            _ -> assertFailure "missing Answers field"
            where
            isAnswers = \case
               Zeek.IpsAttribute Zeek.Answers _ -> True
               _ -> False
            isTtls = \case
               Zeek.Word64sAttribute Zeek.Ttls _ -> True
               _ -> False
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
