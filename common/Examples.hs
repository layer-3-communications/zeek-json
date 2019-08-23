{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
module Examples
  ( encodedKerberosA
  , encodedKerberosB
  , kerberosA
  , kerberosAttrsA
  , kerberosB
  , kerberosAttrsB
  ) where

-- This module is used by both the test suite and the benchmark suite.
-- We pin all of the byte arrays, not for the benefit of the parsers
-- in this module, but so that we can use aeson to get some vaguely
-- comparable performance numbers.

import Zeek.Json (Kerberos(..),Attribute(..),TextField(..))
import Zeek.Json (UidField(..),BoolField(..),TimeField(..))
import Zeek.Json (IpField(..),PortField(..))
import Chronos (Date(..),DayOfMonth(..),Year(..),TimeOfDay(..),Datetime(..))
import Control.Monad.ST (runST)
import Data.Builder (Builder)
import Data.Chunks (Chunks)
import Data.ByteString.Short (ShortByteString,toShort)
import Data.Primitive (ByteArray)
import Data.Text.Encoding (encodeUtf8)
import Data.Text.Short (ShortText)
import Data.Word (Word16)
import Data.WideWord (Word128)
import NeatInterpolation (text)
import Net.Types (IPv4,IP(..),IPv6(..))

import qualified Chronos
import qualified Data.Builder as BDR
import qualified Net.IPv4 as IPv4
import qualified Net.IP as IP
import qualified Data.Maybe.Unpacked.Text.Short as TSM
import qualified Data.Maybe.Unpacked.Numeric.Word128 as MW128
import qualified Data.Maybe.Unpacked as M
import qualified Data.Primitive as PM
import qualified Data.ByteString.Short.Internal as BSS

shortByteStringToByteArray :: ShortByteString -> ByteArray 
shortByteStringToByteArray (BSS.SBS x) = PM.ByteArray x

encodedKerberosA :: ByteArray
encodedKerberosA = pin $ shortByteStringToByteArray $ toShort $ encodeUtf8
  [text|
    {
      "@path": "kerberos",
      "@sensor": "corelight",
      "@timestamp": "2019-08-11T13:02:13.342169Z",
      "id.orig_h": "192.0.2.15",
      "id.orig_p": 52643,
      "id.resp_h": "198.51.100.13",
      "id.resp_p": 445,
      "ts": "2019-08-11T13:01:57.616813Z",
      "uid": "CYKzQg7Uo5Fq9eTQe"
    }
  |]

encodedKerberosB :: ByteArray
encodedKerberosB = pin $ shortByteStringToByteArray $ toShort $ encodeUtf8
  [text|
    {
      "@path": "kerberos",
      "@sensor": "corelight",
      "@timestamp": "2019-08-11T12:59:05.969969Z",
      "cipher": "aes256-cts-hmac-sha1-96",
      "client": "MYHOSTNAM$/OFFICE.EXAMPLE.COM",
      "forwardable": true,
      "id.orig_h": "198.51.100.201",
      "id.orig_p": 54606,
      "id.resp_h": "192.0.2.14",
      "id.resp_p": 88,
      "renewable": true,
      "request_type": "TGS",
      "service": "ldap/desk.office.example.com/office.example.com",
      "success": true,
      "till": "2037-09-13T02:48:05.000000Z",
      "ts": "2019-08-11T12:59:05.870765Z",
      "uid": "CiY9yhn4ZFrMgi7Re"
    }
  |]

kerberosAttrsA :: Chunks Attribute
kerberosAttrsA = kerberosToAttributes kerberosA

kerberosAttrsB :: Chunks Attribute
kerberosAttrsB = kerberosToAttributes kerberosB

kerberosA :: Kerberos
kerberosA = kerberos
  598472073654492522266472486392
  (Datetime (Date (Year 2019) Chronos.august (DayOfMonth 11)) (TimeOfDay 13 1 57_616_813_000))
  (IP.ipv4 192 0 2 15) 52643
  (IP.ipv4 198 51 100 13) 445

kerberosB :: Kerberos
kerberosB =
  ( kerberos
    606324503772025277074419885838
    (Datetime (Date (Year 2019) Chronos.august (DayOfMonth 11)) (TimeOfDay 12 59 5_870_765_000))
    (IP.ipv4 198 51 100 201) 54606
    (IP.ipv4 192 0 2 14) 88
  )
  { request_type = TSM.just "TGS"
  , service = TSM.just "ldap/desk.office.example.com/office.example.com"
  , cipher = TSM.just "aes256-cts-hmac-sha1-96"
  , client = TSM.just "MYHOSTNAM$/OFFICE.EXAMPLE.COM"
  , forwardable = M.just True
  , renewable = M.just True
  , success = M.just True
  , till = M.just $ Datetime
      (Date (Year 2037) Chronos.september (DayOfMonth 13))
      (TimeOfDay 2 48 5_000_000_000)
  }

-- Minimal constructor for kerberos. Initializes everything to nothing
-- except for the fields that are always present.
kerberos ::
     Word128 -- uid
  -> Datetime -- ts
  -> IP -- id.orig_h
  -> Word16 -- id.orig_p
  -> IP -- id.resp_h
  -> Word16 -- id.resp_p
  -> Kerberos
kerberos uid ts id_orig_h id_orig_p id_resp_h id_resp_p = Kerberos
  { auth_ticket = TSM.nothing
  , cipher = TSM.nothing
  , client = TSM.nothing
  , client_cert_fuid = MW128.nothing
  , client_cert_subject = TSM.nothing
  , error_msg = TSM.nothing
  , forwardable = M.nothing
  , from = M.nothing
  , id_orig_h
  , id_orig_p
  , id_resp_h
  , id_resp_p
  , new_ticket = TSM.nothing
  , renewable = M.nothing
  , request_type = TSM.nothing
  , server_cert_fuid = MW128.nothing
  , server_cert_subject = TSM.nothing
  , service = TSM.nothing
  , success = M.nothing
  , till = M.nothing
  , ts
  , uid
  }

pin :: ByteArray -> ByteArray
pin src = runST $ do
  let len = PM.sizeofByteArray src
  dst <- PM.newByteArray len
  PM.copyByteArray dst 0 src 0 len
  PM.unsafeFreezeByteArray dst

kerberosToAttributes :: Kerberos -> Chunks Attribute
kerberosToAttributes (Kerberos
  { auth_ticket , cipher , client , client_cert_fuid , client_cert_subject
  , error_msg , forwardable , from , id_orig_h , id_orig_p
  , id_resp_h , id_resp_p , new_ticket , renewable , request_type
  , server_cert_fuid , server_cert_subject , service , success
  , till , ts , uid }) = BDR.run $
  (TSM.maybe mempty (BDR.singleton . TextAttribute AuthTicket) auth_ticket)
  <> 
  (TSM.maybe mempty (BDR.singleton . TextAttribute Cipher) cipher)
  <> 
  (TSM.maybe mempty (BDR.singleton . TextAttribute Client) client)
  <> 
  (MW128.maybe mempty (BDR.singleton . UidAttribute ClientCertFuid) client_cert_fuid)
  <> 
  (TSM.maybe mempty (BDR.singleton . TextAttribute ClientCertSubject) client_cert_subject)
  <> 
  (TSM.maybe mempty (BDR.singleton . TextAttribute ErrorMessage) error_msg)
  <> 
  (M.maybe mempty (BDR.singleton . BoolAttribute Forwardable) forwardable)
  <> 
  (M.maybe mempty (BDR.singleton . TimeAttribute From) from)
  <> 
  (BDR.singleton (IpAttribute IdOrigHost id_orig_h))
  <> 
  (BDR.singleton (PortAttribute IdOrigPort id_orig_p))
  <> 
  (BDR.singleton (IpAttribute IdRespHost id_resp_h))
  <> 
  (BDR.singleton (PortAttribute IdRespPort id_resp_p))
  <> 
  (TSM.maybe mempty (BDR.singleton . TextAttribute NewTicket) new_ticket)
  <> 
  (M.maybe mempty (BDR.singleton . BoolAttribute Renewable) renewable)
  <> 
  (TSM.maybe mempty (BDR.singleton . TextAttribute RequestType) request_type)
  <> 
  (MW128.maybe mempty (BDR.singleton . UidAttribute ServerCertFuid) server_cert_fuid)
  <> 
  (TSM.maybe mempty (BDR.singleton . TextAttribute ServerCertSubject) server_cert_subject)
  <> 
  (TSM.maybe mempty (BDR.singleton . TextAttribute Service) service)
  <> 
  (M.maybe mempty (BDR.singleton . BoolAttribute Success) success)
  <> 
  (M.maybe mempty (BDR.singleton . TimeAttribute Till) till)
  <> 
  (BDR.singleton (TimeAttribute Timestamp ts))
  <> 
  (BDR.singleton (UidAttribute Uid uid))
