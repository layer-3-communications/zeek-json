{-# language BangPatterns #-}
{-# language DerivingStrategies #-}
{-# language LambdaCase #-}
{-# language MagicHash #-}
{-# language MultiWayIf #-}
{-# language ScopedTypeVariables #-}
{-# language NamedFieldPuns #-}
{-# language TypeApplications #-}

module Zeek.Json
  ( -- * Decode
    decode
  , decodeKerberos
  , ZeekException(..)
  , ZeekParsingException(..)
    -- * Structured
  , Log(..)
  , Kerberos(..)
    -- * Unstructured
  , Attribute(..)
  , BoolField(..)
  , ByteField(..)
  , IpField(..)
  , IpsField(..)
  , TextField(..)
  , TimeField(..)
  , UidField(..)
  , Word16Field(..)
  , Word64sField(..)
  ) where

import Chronos.Types (Year(..),Datetime(..),Date(..),TimeOfDay(..),DayOfMonth(..))
import Control.Monad (when)
import Control.Monad.ST (ST)
import Data.Bool (bool)
import Data.Bytes.Types (Bytes)
import Data.Chunks (Chunks)
import Data.Maybe.Unpacked.Text.Short (MaybeShortText)
import Data.Parser (Parser)
import Data.Primitive (ByteArray,PrimArray)
import Data.Primitive (MutablePrimArray,SmallMutableArray)
import Data.Primitive.Addr (Addr(..))
import Data.Primitive.Unlifted.Array (MutableUnliftedArray(..))
import Data.Text.Short (ShortText)
import Data.WideWord (Word128)
import GHC.Exts (Addr#)
import GHC.Word (Word8(W8#),Word16,Word64)
import Json.Token (TokenException,Token)
import Net.Types (IP(IP),IPv6(IPv6))

import qualified Chronos
import qualified Data.Builder.ST as Builder
import qualified Data.ByteString.Short.Internal as BSS
import qualified Data.Bytes as Bytes
import qualified Data.Bytes.Parser as BP
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Data.Number.Scientific as SCI
import qualified Data.Maybe.Unpacked as M
import qualified Data.Maybe.Unpacked.Numeric.Word128 as MW128
import qualified Data.Maybe.Unpacked.Numeric.Word16 as MW16
import qualified Data.Maybe.Unpacked.Text.Short as TSM
import qualified Data.Parser as P
import qualified Data.Primitive as PM
import qualified Data.Primitive.Addr as PM
import qualified Data.Primitive.Unlifted.Array as PM
import qualified Data.Text.Short as TS
import qualified Data.Text.Short.Unsafe as TS
import qualified Data.Word.Base62 as Base62
import qualified GHC.Exts as Exts
import qualified Json.Token as J
import qualified Net.IP as IP
import qualified Net.IPv4 as IPv4

data Log
  = LogKerberos !Kerberos
  | LogOther

data Kerberos = Kerberos
  { auth_ticket :: {-# UNPACK #-} !MaybeShortText
  , cipher :: {-# UNPACK #-} !MaybeShortText
  , client :: {-# UNPACK #-} !MaybeShortText
  , client_cert_fuid :: {-# UNPACK #-} !MW128.Maybe
  , client_cert_subject :: {-# UNPACK #-} !MaybeShortText
  , error_msg :: {-# UNPACK #-} !MaybeShortText
  , forwardable :: {-# UNPACK #-} !(M.Maybe Bool)
  , from :: {-# UNPACK #-} !(M.Maybe Datetime)
  , id_orig_h :: {-# UNPACK #-} !IP
  , id_orig_p :: {-# UNPACK #-} !Word16
  , id_resp_h :: {-# UNPACK #-} !IP
  , id_resp_p :: {-# UNPACK #-} !Word16
  , new_ticket :: {-# UNPACK #-} !MaybeShortText
  , renewable :: {-# UNPACK #-} !(M.Maybe Bool)
  , request_type :: {-# UNPACK #-} !MaybeShortText
  , server_cert_fuid :: {-# UNPACK #-} !MW128.Maybe
  , server_cert_subject :: {-# UNPACK #-} !MaybeShortText
  , service :: {-# UNPACK #-} !MaybeShortText
  , success :: {-# UNPACK #-} !(M.Maybe Bool)
  , till :: {-# UNPACK #-} !(M.Maybe Datetime)
  , ts :: {-# UNPACK #-} !Datetime
  , uid :: {-# UNPACK #-} !Word128
  }

data TextField
  = AuthTicket
  | Cipher
  | Client
  | ClientCertSubject
  | ErrorMessage
  | NewTicket
  | RequestType
  | ServerCertSubject
  | Service
  | Query
  | QueryTypeName
  | QueryClassName
  | Proto

data UidField
  = ClientCertFuid
  | ServerCertFuid
  | Uid

data IpField
  = IdOrigHost
  | IdRespHost

data IpsField
  = Answers

data Word64sField
  = Ttls

data Word16Field
  = IdOrigPort
  | IdRespPort
  | QueryClass
  | QueryType

data BoolField
  = Forwardable
  | Success
  | Renewable
  | Rejected

data TimeField
  = From
  | To
  | Till
  | Timestamp

data ByteField
  = ResponseCode

data Attribute
  = TextAttribute TextField {-# UNPACK #-} !ShortText
  | UidAttribute UidField {-# UNPACK #-} !Word128
  | BoolAttribute BoolField !Bool
  | TimeAttribute TimeField !Datetime -- intentionally not unpacked. 'decodeDatetime', defined in this same module, is certain to box its result since it calls 'parseByteArray', which in turn calls 'runRW#'.
  | IpAttribute IpField {-# UNPACK #-} !IP
  | IpsAttribute IpsField {-# UNPACK #-} !(PrimArray IPv6)
  | Word64sAttribute Word64sField {-# UNPACK #-} !(PrimArray Word64)
  | Word16Attribute Word16Field {-# UNPACK #-} !Word16
  | ByteAttribute ByteField {-# UNPACK #-} !Word8

newtype KerberosTextField = KerberosTextField Int

kerberosAuthTicket, kerberosCipher, kerberosClient :: KerberosTextField
kerberosClientCertSubject, kerberosErrorMessage, kerberosNewTicket :: KerberosTextField
kerberosRequestType, kerberosServerCertSubject, kerberosService :: KerberosTextField
kerberosTextFieldCount :: Int

kerberosAuthTicket = KerberosTextField 0
kerberosCipher = KerberosTextField 1
kerberosClient = KerberosTextField 2
kerberosClientCertSubject = KerberosTextField 3
kerberosErrorMessage = KerberosTextField 4
kerberosNewTicket = KerberosTextField 5
kerberosRequestType = KerberosTextField 6
kerberosServerCertSubject = KerberosTextField 7
kerberosService = KerberosTextField 8
kerberosTextFieldCount = 9

newtype KerberosBoolField = KerberosBoolField Int

kerberosRenewable,kerberosSuccess,kerberosForwardable :: KerberosBoolField
kerberosBoolFieldCount :: Int

kerberosRenewable = KerberosBoolField 0
kerberosSuccess = KerberosBoolField 1
kerberosForwardable = KerberosBoolField 2
kerberosBoolFieldCount = 3

newtype KerberosPortField = KerberosPortField Int

kerberosIdOrigPort,kerberosIdRespPort :: KerberosPortField
kerberosPortFieldCount :: Int

kerberosIdOrigPort = KerberosPortField 0
kerberosIdRespPort = KerberosPortField 1
kerberosPortFieldCount = 2

-- This is used for both UIDs and IP addresses.
newtype KerberosWord128Field = KerberosWord128Field Int

kerberosIdOrigHost,kerberosIdRespHost,kerberosClientCertFuid :: KerberosWord128Field
kerberosServerCertFuid,kerberosUid :: KerberosWord128Field
kerberosWord128FieldCount :: Int

kerberosIdOrigHost = KerberosWord128Field 0
kerberosIdRespHost = KerberosWord128Field 1
kerberosClientCertFuid = KerberosWord128Field 2
kerberosServerCertFuid = KerberosWord128Field 3
kerberosUid = KerberosWord128Field 4
kerberosWord128FieldCount = 5

newtype KerberosTimeField = KerberosTimeField Int

kerberosTimestamp,kerberosFrom,kerberosTill :: KerberosTimeField
kerberosTimeFieldCount :: Int

kerberosTimestamp = KerberosTimeField 0 -- From the field named @ts@
kerberosFrom = KerberosTimeField 1
kerberosTill = KerberosTimeField 2
kerberosTimeFieldCount = 3

data Scratchpad s = Scratchpad
  { texts :: !(MutableUnliftedArray s ShortText)
  , bools :: !(MutablePrimArray s Word8)
  , times :: !(SmallMutableArray s Datetime)
  , ports :: !(MutablePrimArray s Word16)
  , word128s :: !(MutablePrimArray s Word128)
  , writes :: !(MutablePrimArray s Word8)
    -- ^ Size is the sum of the sizes of the other arrays
  }

data ZeekException
  = Lexing TokenException
  | Parsing ZeekParsingException
  deriving stock (Show)

data ZeekParsingException
  = IncompleteArray
  | IncompleteObject
  | InvalidAnswers
  | InvalidAuthTicket
  | InvalidQueryClass
  | InvalidQueryClassName
  | InvalidCipher
  | InvalidClient
  | InvalidClientCertFuid
  | InvalidClientCertSubject
  | InvalidErrorMessage
  | InvalidForwardable
  | InvalidFrom
  | InvalidIdOrigHost
  | InvalidIdOrigPort
  | InvalidIdRespHost
  | InvalidIdRespPort
  | InvalidNewTicket
  | InvalidObjectKey
  | InvalidObjectPair
  | InvalidArraySeparator
  | InvalidObjectSeparator Token
  | InvalidProto
  | InvalidQuery
  | InvalidQueryType
  | InvalidQueryTypeName
  | InvalidRejected
  | InvalidRenewable
  | InvalidRequestType
  | InvalidResponseCode
  | InvalidServer
  | InvalidServerCertFuid
  | InvalidServerCertSubject
  | InvalidService
  | InvalidSuccess
  | InvalidTill
  | InvalidTimestamp
  | InvalidTtls
  | InvalidUid
  | MissingIdOrigHost
  | MissingIdOrigPort
  | MissingIdRespHost
  | MissingIdRespPort
  | MissingUid
  | MissingTimestamp
  | NotObject
  deriving stock (Show)

offsetKerberosTexts :: Int
offsetKerberosTexts = 0

offsetKerberosBools :: Int
offsetKerberosBools = offsetKerberosTexts + kerberosTextFieldCount

offsetKerberosTimes :: Int
offsetKerberosTimes = offsetKerberosBools + kerberosBoolFieldCount

offsetKerberosPorts :: Int
offsetKerberosPorts = offsetKerberosTimes + kerberosTimeFieldCount

offsetKerberosWord128s :: Int
offsetKerberosWord128s = offsetKerberosPorts + kerberosPortFieldCount

errorThunk :: a
{-# noinline errorThunk #-}
errorThunk = error "Zeek.Json: mistake was made"

decode :: Bytes -> Either ZeekException (Chunks Attribute)
decode b = case J.decode b of
  Left e -> Left (Lexing e)
  Right tokens -> case P.parseSmallArray parserAttributes tokens of
    -- TODO: should we use the length?
    P.Success (P.Slice _ _ k) -> Right k
    P.Failure e -> Left (Parsing e)

parserAttributes :: Parser Token ZeekParsingException s (Chunks Attribute)
parserAttributes = do
  P.token NotObject J.LeftBrace
  bdr <- P.foldSepBy1
    ( P.any IncompleteObject >>= \case
        J.Comma -> pure True
        J.RightBrace -> pure False
        t -> P.fail (InvalidObjectSeparator t)
    )
    (\bdr -> do
        key <- string InvalidObjectKey
        P.token InvalidObjectPair J.Colon
        attributeValue key bdr
    ) =<< P.effect Builder.new
  P.effect (Builder.freeze bdr)

decodeKerberos :: Bytes -> Either ZeekException Kerberos
decodeKerberos b = case J.decode b of
  Left e -> Left (Lexing e)
  Right tokens -> case P.parseSmallArray parserKerberos tokens of
    -- TODO: should we use the length for anything?
    P.Success (P.Slice _ _ k) -> Right k
    P.Failure e -> Left (Parsing e)

newKerberosScratchPad :: ST s (Scratchpad s)
newKerberosScratchPad = do
  texts' <- PM.newUnliftedArray kerberosTextFieldCount (mempty :: ByteArray)
  bools <- PM.newPrimArray kerberosBoolFieldCount
  times <- PM.newSmallArray kerberosTimeFieldCount errorThunk
  ports <- PM.newPrimArray kerberosPortFieldCount
  word128s <- PM.newPrimArray kerberosWord128FieldCount
  let totalKerberosWrites = 0
        + kerberosTextFieldCount
        + kerberosBoolFieldCount
        + kerberosTimeFieldCount
        + kerberosPortFieldCount
        + kerberosWord128FieldCount
  writes <- PM.newPrimArray totalKerberosWrites
  PM.setPrimArray writes 0 totalKerberosWrites (0 :: Word8)
  let texts = case texts' of MutableUnliftedArray y -> MutableUnliftedArray y
  pure Scratchpad {texts,times,bools,ports,word128s,writes}

parserKerberos :: Parser Token ZeekParsingException s Kerberos
parserKerberos = do
  P.token NotObject J.LeftBrace
  scratchpad@(Scratchpad {texts,bools,ports,word128s,times,writes}) <-
    P.effect newKerberosScratchPad
  P.sepBy1
    ( P.any IncompleteObject >>= \case
        J.Comma -> pure True
        J.RightBrace -> pure False
        t -> P.fail (InvalidObjectSeparator t)
    )
    (do key <- string InvalidObjectKey
        P.token InvalidObjectPair J.Colon
        kerberosValue scratchpad key
    )
  -- Mandatory Fields
  id_orig_p <- P.effect (readKerberosPort ports writes kerberosIdOrigPort)
    >>= MW16.maybe (P.fail MissingIdOrigPort) pure
  id_resp_p <- P.effect (readKerberosPort ports writes kerberosIdRespPort)
    >>= MW16.maybe (P.fail MissingIdRespPort) pure
  id_orig_h <- P.effect (readKerberosWord128 word128s writes kerberosIdOrigHost)
    >>= MW128.maybe (P.fail MissingIdOrigHost) (pure . IP . IPv6)
  id_resp_h <- P.effect (readKerberosWord128 word128s writes kerberosIdRespHost)
    >>= MW128.maybe (P.fail MissingIdRespHost) (pure . IP . IPv6)
  uid <- P.effect (readKerberosWord128 word128s writes kerberosUid)
    >>= MW128.maybe (P.fail MissingUid) pure
  ts <- P.effect (readKerberosTime times writes kerberosTimestamp)
    >>= M.maybe (P.fail MissingTimestamp) pure
  -- Optional Fields
  P.effect $ do
    auth_ticket <- readKerberosText texts writes kerberosAuthTicket
    cipher <- readKerberosText texts writes kerberosCipher
    client <- readKerberosText texts writes kerberosClient
    client_cert_subject <- readKerberosText texts writes kerberosClientCertSubject
    server_cert_subject <- readKerberosText texts writes kerberosServerCertSubject
    forwardable <- readKerberosBool bools writes kerberosForwardable
    success <- readKerberosBool bools writes kerberosSuccess
    renewable <- readKerberosBool bools writes kerberosRenewable
    request_type <- readKerberosText texts writes kerberosRequestType
    service <- readKerberosText texts writes kerberosService
    error_msg <- readKerberosText texts writes kerberosErrorMessage
    new_ticket <- readKerberosText texts writes kerberosNewTicket
    till <- readKerberosTime times writes kerberosTill
    from <- readKerberosTime times writes kerberosFrom
    client_cert_fuid <- readKerberosWord128 word128s writes kerberosClientCertFuid
    server_cert_fuid <- readKerberosWord128 word128s writes kerberosServerCertFuid
    pure $ Kerberos
      { auth_ticket,cipher,client,client_cert_subject,forwardable
      , success, renewable, server_cert_subject, id_orig_p, id_resp_p
      , request_type, service, error_msg, ts
      , id_resp_h, id_orig_h, uid, till, from, client_cert_fuid
      , server_cert_fuid, new_ticket
      }

uidToken :: e -> Parser Token e s Word128
uidToken e = P.any e >>= \case
  J.String str -> case Base62.decode128 (Bytes.fromByteArray (shortTextToByteArray str)) of
    Nothing -> P.fail e
    Just w -> pure w
  _ -> P.fail e

timeToken :: e -> Parser Token e s Datetime
timeToken e = P.any e >>= \case
  J.String str -> case decodeDatetime str of
    Nothing -> P.fail e
    Just w -> pure w
  _ -> P.fail e

-- Recognizes both IPv4 and IPv6 formats.
ip :: e -> Parser Token e s Word128
ip e = P.any e >>= \case
  J.String str -> case IP.decodeShort str of
    Nothing -> P.fail e
    Just (IP (IPv6 w)) -> pure w
  _ -> P.fail e

word64s ::
     ZeekParsingException
  -> Parser Token ZeekParsingException s (PrimArray Word64)
word64s e = do
  P.token e J.LeftBracket
  P.any e >>= \case
    J.RightBracket -> pure mempty
    tok -> do
      let initSz = 3
      marr0 <- P.effect (PM.newPrimArray initSz)
      decipher tok marr0 0 initSz
  where
  eat !marr !ix !len = P.any IncompleteArray >>= \case
    J.Comma -> do
      t <- P.any e
      decipher t marr ix len
    J.RightBracket -> P.effect $ do
      PM.shrinkMutablePrimArray marr ix
      PM.unsafeFreezePrimArray marr
    _ -> P.fail InvalidArraySeparator
  decipher !tok !marr !ix !len = case len of
    0 -> do
      marr' <- P.effect (PM.resizeMutablePrimArray marr (ix * 2))
      decipher tok marr' ix ix
    _ -> case tok of
      J.Number n -> case SCI.toWord64 n of
        Nothing -> P.fail e
        Just w -> do
          P.effect (PM.writePrimArray marr ix w)
          eat marr (ix + 1) (len - 1)
      _ -> P.fail e

ips :: ZeekParsingException -> Parser Token ZeekParsingException s (PrimArray IPv6)
ips e = do
  P.token e J.LeftBracket
  P.any e >>= \case
    J.RightBracket -> pure mempty
    J.String str -> do
      let initSz = 3
      marr0 <- P.effect (PM.newPrimArray initSz)
      decipher str marr0 0 initSz
    _ -> P.fail e
  where
  eat !marr !ix !len = P.any IncompleteArray >>= \case
    J.Comma -> P.any e >>= \case
      J.String str -> decipher str marr ix len
      _ -> P.fail e
    J.RightBracket -> P.effect $ do
      PM.shrinkMutablePrimArray marr ix
      PM.unsafeFreezePrimArray marr
    _ -> P.fail InvalidArraySeparator
  decipher !str !marr !ix !len = case len of
    0 -> do
      marr' <- P.effect (PM.resizeMutablePrimArray marr (ix * 2))
      decipher str marr' ix ix
    _ -> case IPv4.decodeShort str of
      Nothing -> P.fail e
      Just addrA -> do
        let IP addrB = IP.fromIPv4 addrA
        P.effect (PM.writePrimArray marr ix addrB)
        eat marr (ix + 1) (len - 1)

word8 :: e -> Parser Token e s Word8
word8 e = P.any e >>= \case
  J.Number n -> case SCI.toWord8 n of
    Nothing -> P.fail e
    Just w -> pure w
  _ -> P.fail e

word16 :: e -> Parser Token e s Word16
word16 e = P.any e >>= \case
  J.Number n -> case SCI.toWord16 n of
    Nothing -> P.fail e
    Just w -> pure w
  _ -> P.fail e

string :: e -> Parser Token e s ShortText
string e = P.any e >>= \case
  J.String str -> pure str
  _ -> P.fail e

boolean :: e -> Parser Token e s Bool
boolean e = P.any e >>= \case
  J.BooleanTrue -> pure True
  J.BooleanFalse -> pure False
  _ -> P.fail e

-- uid :: () -> Parser Token () Word128
-- uid e = do
--   n <- P.any e
--   case JN.toWord16 n of
--     Nothing -> P.fail e
--     Just w -> pure w

-- Precondition: the key is not the empty string. See kerberosValue.
attributeValue ::
     ShortText
  -> Builder.Builder s Attribute
  -> Parser Token ZeekParsingException s (Builder.Builder s Attribute)
attributeValue !key !bdr = case unsafeShortTextHead key of
  'a' -> case len of
    07 -> if | eqShortTextAddr key "answers"# ->
                 ipsAttr Answers InvalidAnswers bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    11 -> if | eqShortTextAddr key "auth_ticket"# ->
                 stringAttr AuthTicket InvalidAuthTicket bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    _ -> bdr <$ P.any IncompleteObject
  'c' -> case len of
    06 -> if | eqShortTextAddr key "cipher"# ->
                 stringAttr Cipher InvalidCipher bdr
             | eqShortTextAddr key "client"# ->
                 stringAttr Client InvalidClient bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    19 -> if | eqShortTextAddr key "client_cert_subject"# ->
                 stringAttr ClientCertSubject InvalidClientCertSubject bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    _ -> bdr <$ P.any IncompleteObject
  'f' -> case len of
    11 -> if | eqShortTextAddr key "forwardable"# ->
                 boolAttr Forwardable InvalidForwardable bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    _ -> bdr <$ P.any IncompleteObject
  'i' -> case len of
    09 -> if | eqShortTextAddr key "id.orig_p"# ->
                 portAttr IdOrigPort InvalidIdOrigPort bdr
             | eqShortTextAddr key "id.resp_p"# ->
                 portAttr IdRespPort InvalidIdRespPort bdr
             | eqShortTextAddr key "id.orig_h"# ->
                 ipAttr IdOrigHost InvalidIdOrigHost bdr
             | eqShortTextAddr key "id.resp_h"# ->
                 ipAttr IdRespHost InvalidIdRespHost bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    _ -> bdr <$ P.any IncompleteObject
  'p' -> case len of
    05 -> if | eqShortTextAddr key "proto"# ->
                 stringAttr Proto InvalidProto bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    _ -> bdr <$ P.any IncompleteObject
  'q' -> case len of
    05 -> if | eqShortTextAddr key "query"# ->
                 stringAttr Query InvalidQuery bdr
             | eqShortTextAddr key "qtype"# ->
                 portAttr QueryType InvalidQueryType bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    06 -> if | eqShortTextAddr key "qclass"# ->
                 portAttr QueryClass InvalidQueryClass bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    10 -> if | eqShortTextAddr key "qtype_name"# ->
                 stringAttr QueryTypeName InvalidQueryTypeName bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    11 -> if | eqShortTextAddr key "qclass_name"# ->
                 stringAttr QueryClassName InvalidQueryClassName bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    _ -> bdr <$ P.any IncompleteObject
  'r' -> case len of
    05 -> if | eqShortTextAddr key "rcode"# ->
                 byteAttr ResponseCode InvalidResponseCode bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    08 -> if | eqShortTextAddr key "rejected"# ->
                 boolAttr Rejected InvalidRejected bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    09 -> if | eqShortTextAddr key "renewable"# ->
                 boolAttr Renewable InvalidRenewable bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    12 -> if | eqShortTextAddr key "request_type"# ->
                 stringAttr RequestType InvalidRequestType bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    _ -> bdr <$ P.any IncompleteObject
  's' -> case len of
    07 -> if | eqShortTextAddr key "service"# ->
                 stringAttr Service InvalidService bdr
             | eqShortTextAddr key "success"# ->
                 boolAttr Success InvalidSuccess bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    _ -> bdr <$ P.any IncompleteObject
  't' -> case len of
    02 -> if | eqShortTextAddr key "ts"# ->
                 timeAttr Timestamp InvalidTimestamp bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    04 -> if | eqShortTextAddr key "till"# ->
                 timeAttr Till InvalidTill bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    _ -> bdr <$ P.any IncompleteObject
  'T' -> if | eqShortTextAddr key "TTLs"# -> do
                word64sAttr Ttls InvalidTtls bdr
            | otherwise -> bdr <$ P.any IncompleteObject
  'u' -> case len of
    03 -> if | eqShortTextAddr key "uid"# ->
                 uidAttr Uid InvalidUid bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    _ -> bdr <$ P.any IncompleteObject
  _ -> bdr <$ P.any IncompleteObject
  where
  len = PM.sizeofByteArray (shortTextToByteArray key)

stringAttr ::
     TextField
  -> ZeekParsingException
  -> Builder.Builder s Attribute
  -> Parser Token ZeekParsingException s (Builder.Builder s Attribute)
stringAttr field err bdr = do
  str <- string err
  let !attr = TextAttribute field str
  P.effect (Builder.push attr bdr)

boolAttr ::
     BoolField
  -> ZeekParsingException
  -> Builder.Builder s Attribute
  -> Parser Token ZeekParsingException s (Builder.Builder s Attribute)
boolAttr field err bdr = do
  str <- boolean err
  let !attr = BoolAttribute field str
  P.effect (Builder.push attr bdr)

timeAttr ::
     TimeField
  -> ZeekParsingException
  -> Builder.Builder s Attribute
  -> Parser Token ZeekParsingException s (Builder.Builder s Attribute)
timeAttr field err bdr = do
  u <- timeToken err
  let !attr = TimeAttribute field u
  P.effect (Builder.push attr bdr)

uidAttr ::
     UidField
  -> ZeekParsingException
  -> Builder.Builder s Attribute
  -> Parser Token ZeekParsingException s (Builder.Builder s Attribute)
uidAttr field err bdr = do
  u <- uidToken err
  let !attr = UidAttribute field u
  P.effect (Builder.push attr bdr)

ipAttr ::
     IpField
  -> ZeekParsingException
  -> Builder.Builder s Attribute
  -> Parser Token ZeekParsingException s (Builder.Builder s Attribute)
ipAttr field err bdr = do
  str <- ip err
  let !attr = IpAttribute field (IP (IPv6 str))
  P.effect (Builder.push attr bdr)

ipsAttr ::
     IpsField
  -> ZeekParsingException
  -> Builder.Builder s Attribute
  -> Parser Token ZeekParsingException s (Builder.Builder s Attribute)
ipsAttr field err bdr = do
  v <- ips err
  let !attr = IpsAttribute field v
  P.effect (Builder.push attr bdr)

word64sAttr ::
     Word64sField
  -> ZeekParsingException
  -> Builder.Builder s Attribute
  -> Parser Token ZeekParsingException s (Builder.Builder s Attribute)
word64sAttr field err bdr = do
  v <- word64s err
  let !attr = Word64sAttribute field v
  P.effect (Builder.push attr bdr)

portAttr ::
     Word16Field
  -> ZeekParsingException
  -> Builder.Builder s Attribute
  -> Parser Token ZeekParsingException s (Builder.Builder s Attribute)
portAttr field err bdr = do
  str <- word16 err
  let !attr = Word16Attribute field str
  P.effect (Builder.push attr bdr)

byteAttr ::
     ByteField
  -> ZeekParsingException
  -> Builder.Builder s Attribute
  -> Parser Token ZeekParsingException s (Builder.Builder s Attribute)
byteAttr field err bdr = do
  str <- word8 err
  let !attr = ByteAttribute field str
  P.effect (Builder.push attr bdr)

-- Precondition: the key is not the empty string
-- To accelerate lookup, we consider the first character before
-- scanning the list of possible keys. This is kind of like a
-- crummy version of reifying a compressed trie as code. However,
-- doing that would be tedious and brittle. It would be an interesting
-- experiment to try adding support for that to GHC.
kerberosValue :: Scratchpad s -> ShortText -> Parser Token ZeekParsingException s ()
kerberosValue (Scratchpad{texts,bools,ports,word128s,times,writes}) !key = case unsafeShortTextHead key of
  'a' -> if | eqShortTextAddr key "auth_ticket"# ->
                string InvalidAuthTicket
                  >>= P.effect . writeKerberosText texts writes kerberosAuthTicket
            | otherwise -> () <$ P.any IncompleteObject
  'e' -> if | eqShortTextAddr key "error_msg"# ->
                string InvalidErrorMessage
                  >>= P.effect . writeKerberosText texts writes kerberosErrorMessage
            | otherwise -> () <$ P.any IncompleteObject
  'n' -> if | eqShortTextAddr key "new_ticket"# ->
                string InvalidNewTicket
                  >>= P.effect . writeKerberosText texts writes kerberosNewTicket
            | otherwise -> () <$ P.any IncompleteObject
  'f' -> if | eqShortTextAddr key "forwardable"# ->
                boolean InvalidForwardable
                  >>= P.effect . writeKerberosBool bools writes kerberosForwardable
            | eqShortTextAddr key "from"# ->
                timeToken InvalidFrom
                  >>= P.effect . writeKerberosTime times writes kerberosFrom
            | otherwise -> () <$ P.any IncompleteObject
  'r' -> if | eqShortTextAddr key "renewable"# ->
                boolean InvalidRenewable
                  >>= P.effect . writeKerberosBool bools writes kerberosRenewable
            | eqShortTextAddr key "request_type"# ->
                string InvalidRequestType
                  >>= P.effect . writeKerberosText texts writes kerberosRequestType
            | otherwise -> () <$ P.any IncompleteObject
  'i' -> if | eqShortTextAddr key "id.orig_p"# ->
                word16 InvalidIdOrigPort
                  >>= P.effect . writeKerberosPort ports writes kerberosIdOrigPort
            | eqShortTextAddr key "id.resp_p"# ->
                word16 InvalidIdRespPort
                  >>= P.effect . writeKerberosPort ports writes kerberosIdRespPort
            | eqShortTextAddr key "id.orig_h"# ->
                ip InvalidIdOrigHost
                  >>= P.effect . writeKerberosWord128 word128s writes kerberosIdOrigHost
            | eqShortTextAddr key "id.resp_h"# ->
                ip InvalidIdRespHost
                  >>= P.effect . writeKerberosWord128 word128s writes kerberosIdRespHost
            | otherwise -> () <$ P.any IncompleteObject
  'u' -> if | eqShortTextAddr key "uid"# ->
                uidToken InvalidUid
                  >>= P.effect . writeKerberosWord128 word128s writes kerberosUid
            | otherwise -> () <$ P.any IncompleteObject
  'c' -> if | eqShortTextAddr key "cipher"# ->
                string InvalidCipher
                  >>= P.effect . writeKerberosText texts writes kerberosCipher
            | eqShortTextAddr key "client"# ->
                string InvalidClient
                  >>= P.effect . writeKerberosText texts writes kerberosClient
            | eqShortTextAddr key "client_cert_subject"# ->
                string InvalidClientCertSubject
                  >>= P.effect . writeKerberosText texts writes kerberosClientCertSubject
            | eqShortTextAddr key "server_cert_fuid"# ->
                uidToken InvalidClientCertFuid
                  >>= P.effect . writeKerberosWord128 word128s writes kerberosClientCertFuid
            | otherwise -> () <$ P.any IncompleteObject
  's' -> if | eqShortTextAddr key "success"# ->
                boolean InvalidSuccess
                  >>= P.effect . writeKerberosBool bools writes kerberosSuccess
            | eqShortTextAddr key "service"# ->
                string InvalidService
                  >>= P.effect . writeKerberosText texts writes kerberosService
            | eqShortTextAddr key "server_cert_subject"# ->
                string InvalidServerCertSubject
                  >>= P.effect . writeKerberosText texts writes kerberosServerCertSubject
            | eqShortTextAddr key "server_cert_fuid"# ->
                uidToken InvalidServerCertFuid
                  >>= P.effect . writeKerberosWord128 word128s writes kerberosServerCertFuid
            | otherwise -> () <$ P.any IncompleteObject
  't' -> if | eqShortTextAddr key "ts"# ->
                timeToken InvalidTimestamp
                  >>= P.effect . writeKerberosTime times writes kerberosTimestamp
            | eqShortTextAddr key "till"# ->
                timeToken InvalidTill
                  >>= P.effect . writeKerberosTime times writes kerberosTill
            | otherwise -> () <$ P.any IncompleteObject
  _ -> () <$ P.any IncompleteObject

-- This will always report false if the text argument has a null
-- character in it since the addr is assumed to be null terminated.
-- This does not matter though since none of the expected keys
-- have null characters.
eqShortTextAddr :: ShortText -> Addr# -> Bool
eqShortTextAddr str addr# = go 0
  where
  addr = Addr addr#
  bs = shortTextToByteArray str
  !len = PM.sizeofByteArray bs
  go !ix = if ix < len
    then
      let !(expected :: Word8) = PM.indexOffAddr addr ix
       in if expected == 0
            then False
            else expected == PM.indexByteArray bs ix && go (ix + 1)
    else PM.indexOffAddr addr ix == (0 :: Word8)

-- This only works correctly if the head is an ASCII character, but
-- we do not care about that in this module since none of
-- the keys in the JSON encoding of bro logs have any non-ascii
-- characters. If someone does send a logs with a key that starts
-- with a non-ascii character, this will misinterpret it, but
-- the parser will end up rejecting that key, which is the
-- behavior we want anyway.
unsafeShortTextHead :: ShortText -> Char
unsafeShortTextHead str = case PM.indexByteArray (shortTextToByteArray str) 0 of
  W8# w -> Exts.C# (Exts.chr# (Exts.word2Int# w))

readKerberosText ::
     MutableUnliftedArray s ShortText
  -> MutablePrimArray s Word8
  -> KerberosTextField
  -> ST s MaybeShortText
readKerberosText marr writes (KerberosTextField field) = do
  PM.readPrimArray writes (field + offsetKerberosTexts) >>= \case
    1 -> fmap TSM.just (readTextArray marr (fromEnum field))
    _ -> pure TSM.nothing

readKerberosTime ::
     SmallMutableArray s Datetime
  -> MutablePrimArray s Word8
  -> KerberosTimeField
  -> ST s (M.Maybe Datetime)
readKerberosTime marr writes (KerberosTimeField field) = do
  PM.readPrimArray writes (field + offsetKerberosTimes) >>= \case
    1 -> fmap M.just (PM.readSmallArray marr field)
    _ -> pure M.nothing

readKerberosPort ::
     MutablePrimArray s Word16
  -> MutablePrimArray s Word8
  -> KerberosPortField
  -> ST s MW16.Maybe
readKerberosPort marr writes (KerberosPortField field) = do
  PM.readPrimArray writes (field + offsetKerberosPorts) >>= \case
    1 -> fmap MW16.just (PM.readPrimArray marr field)
    _ -> pure MW16.nothing

readKerberosWord128 ::
     MutablePrimArray s Word128
  -> MutablePrimArray s Word8
  -> KerberosWord128Field
  -> ST s MW128.Maybe
readKerberosWord128 marr writes (KerberosWord128Field field) = do
  PM.readPrimArray writes (field + offsetKerberosWord128s) >>= \case
    1 -> fmap MW128.just (PM.readPrimArray marr field)
    _ -> pure MW128.nothing


readKerberosBool ::
     MutablePrimArray s Word8
  -> MutablePrimArray s Word8
  -> KerberosBoolField
  -> ST s (M.Maybe Bool)
readKerberosBool marr writes (KerberosBoolField field) = do
  PM.readPrimArray writes (field + offsetKerberosBools) >>= \case
    1 -> do
      PM.readPrimArray marr field >>= \case
        1 -> pure (M.just True)
        _ -> pure (M.just False)
    _ -> pure M.nothing

writeKerberosText ::
     MutableUnliftedArray s ShortText -- array of texts
  -> MutablePrimArray s Word8 -- array to track writes
  -> KerberosTextField
  -> ShortText
  -> ST s ()
writeKerberosText marr writes field str = do
  let KerberosTextField ix = field
  writeTextArray marr ix str
  PM.writePrimArray writes (ix + offsetKerberosTexts) (1 :: Word8)

writeKerberosTime ::
     SmallMutableArray s Datetime -- array of texts
  -> MutablePrimArray s Word8 -- array to track writes
  -> KerberosTimeField
  -> Datetime
  -> ST s ()
writeKerberosTime marr writes field time = do
  let KerberosTimeField ix = field
  PM.writeSmallArray marr ix time
  PM.writePrimArray writes (ix + offsetKerberosTimes) (1 :: Word8)

writeKerberosPort ::
     MutablePrimArray s Word16 -- array of ports
  -> MutablePrimArray s Word8 -- array to track writes
  -> KerberosPortField
  -> Word16
  -> ST s ()
writeKerberosPort marr writes field w = do
  let KerberosPortField ix = field
  PM.writePrimArray marr ix w
  PM.writePrimArray writes (ix + offsetKerberosPorts) (1 :: Word8)

writeKerberosWord128 ::
     MutablePrimArray s Word128 -- array of ports
  -> MutablePrimArray s Word8 -- array to track writes
  -> KerberosWord128Field
  -> Word128
  -> ST s ()
writeKerberosWord128 marr writes field w = do
  let KerberosWord128Field ix = field
  PM.writePrimArray marr ix w
  PM.writePrimArray writes (ix + offsetKerberosWord128s) (1 :: Word8)

writeKerberosBool ::
     MutablePrimArray s Word8 -- array of bools
  -> MutablePrimArray s Word8 -- array to track writes
  -> KerberosBoolField
  -> Bool
  -> ST s ()
writeKerberosBool marr writes field b = do
  let KerberosBoolField ix = field
  PM.writePrimArray marr ix (bool (0 :: Word8) 1 b)
  PM.writePrimArray writes (ix + offsetKerberosBools) (1 :: Word8)

readTextArray :: MutableUnliftedArray s ShortText -> Int -> ST s ShortText
readTextArray !(MutableUnliftedArray marr) !ix =
  fmap byteArrayToShortText (PM.readUnliftedArray (MutableUnliftedArray marr) ix)

writeTextArray :: MutableUnliftedArray s ShortText -> Int -> ShortText -> ST s ()
writeTextArray !(MutableUnliftedArray marr) !ix !str =
  PM.writeUnliftedArray (MutableUnliftedArray marr) ix (shortTextToByteArray str)

-- Check that everything was set to 1. They all started out as 0.
-- validate ::
--      Int -- size of bool array
--   -> MutablePrimArray s Word8 -- bool array
--   -> ST s Bool
-- validate sz arr = go (sz - 1) where
--   go ix = if ix >= 0
--     then PM.readPrimArray arr ix >>= \case
--       1 -> go (ix - 1)
--       _ -> pure False
--     else pure True

byteArrayToShortByteString :: ByteArray -> BSS.ShortByteString
byteArrayToShortByteString (PM.ByteArray x) = BSS.SBS x

shortByteStringToByteArray :: BSS.ShortByteString -> ByteArray
shortByteStringToByteArray (BSS.SBS x) = PM.ByteArray x

-- This is unsafe. It does not validate that the bytes are a
-- valid UTF-8 encoding of anything. This is only used internally
-- in situations where we are certain that this precondition holds.
byteArrayToShortText :: ByteArray -> ShortText
byteArrayToShortText str = TS.fromShortByteStringUnsafe (byteArrayToShortByteString str)

shortTextToByteArray :: ShortText -> ByteArray
shortTextToByteArray = shortByteStringToByteArray . TS.toShortByteString

decodeDatetime :: ShortText -> Maybe Datetime
decodeDatetime str = case BP.parseByteArray parserDatetime (shortTextToByteArray str) of
  BP.Success (BP.Slice _ remaining datetime) -> case remaining of
    0 -> Just datetime
    _ -> Nothing
  BP.Failure _ -> Nothing

parserDatetime :: BP.Parser () s Datetime
parserDatetime = do
  year <- Latin.decWord16 ()
  Latin.char () '-'
  month0 <- Latin.decWord8 ()
  let month1 = fromIntegral @Word8 @Word8 month0 - 1
  when (month1 >= 12) (BP.fail ())
  Latin.char () '-'
  day <- Latin.decWord8 ()
  Latin.char () 'T'
  hour <- Latin.decWord8 ()
  when (hour >= 24) (BP.fail ())
  Latin.char () ':'
  minute <- Latin.decWord8 ()
  when (minute >= 60) (BP.fail ())
  Latin.char () ':'
  second <- Latin.decWord8 ()
  when (second >= 60) (BP.fail ())
  Latin.char () '.'
  microsecond <- Latin.decWord32 ()
  when (microsecond >= 1000000) (BP.fail ())
  Latin.char () 'Z'
  pure $ Chronos.Datetime
    (Chronos.Date
      (Chronos.Year (fromIntegral year))
      (Chronos.Month (fromIntegral month1))
      (Chronos.DayOfMonth (fromIntegral day))
    )
    (Chronos.TimeOfDay
      (fromIntegral hour)
      (fromIntegral minute)
      ((fromIntegral second * 1000000 + fromIntegral microsecond) * 1000)
    )
