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
    -- * Structured
  , Log(..)
  , Kerberos(..)
    -- * Unstructured
  , Attribute(..)
  , TextField(..)
  , UidField(..)
  , BoolField(..)
  , TimeField(..)
  , IpField(..)
  , PortField(..)
  ) where

import Chronos.Types (Year(..),Datetime(..),Date(..),TimeOfDay(..),DayOfMonth(..))
import Control.Monad (when)
import Control.Monad.ST (ST)
import Data.Bool (bool)
import Data.Bytes.Types (Bytes)
import Data.Chunks (Chunks)
import Data.Json.Tokenize (JsonTokenizeException)
import Data.Json.Tokenize (Token)
import Data.Maybe.Unpacked.Text.Short (MaybeShortText)
import Data.Parser (Parser)
import Data.Primitive (ByteArray)
import Data.Primitive (MutablePrimArray,SmallMutableArray)
import Data.Primitive.Addr (Addr(..))
import Data.Primitive.Unlifted.Array (MutableUnliftedArray(..))
import Data.Text.Short (ShortText)
import Data.WideWord (Word128)
import GHC.Exts (Addr#)
import GHC.Word (Word8(W8#),Word16)
import Net.Types (IPv4,IP(IP),IPv6(IPv6))

import qualified Chronos
import qualified Data.Builder.ST as Builder
import qualified Data.ByteString.Short.Internal as BSS
import qualified Data.Bytes as Bytes
import qualified Data.Bytes.Parser as BP
import qualified Data.Json.Number as JN
import qualified Data.Json.Tokenize as J
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

data UidField
  = ClientCertFuid
  | ServerCertFuid
  | Uid

data IpField
  = IdOrigHost
  | IdRespHost

data PortField
  = IdOrigPort
  | IdRespPort

data BoolField
  = Forwardable
  | Success
  | Renewable

data TimeField
  = From
  | To
  | Till
  | Timestamp

data Attribute
  = TextAttribute TextField {-# UNPACK #-} !ShortText
  | UidAttribute UidField {-# UNPACK #-} !Word128
  | BoolAttribute BoolField !Bool
  | TimeAttribute TimeField !Datetime -- intentionally not unpacked
  | IpAttribute IpField {-# UNPACK #-} !IP
  | PortAttribute PortField {-# UNPACK #-} !Word16

data KerberosTextField
  = KerberosAuthTicket
  | KerberosCipher
  | KerberosClient
  | KerberosClientCertSubject
  | KerberosErrorMessage
  | KerberosNewTicket
  | KerberosRequestType
  | KerberosServerCertSubject
  | KerberosService
  deriving stock (Bounded,Enum)

data KerberosBoolField
  = KerberosRenewable
  | KerberosSuccess
  | KerberosForwardable
  deriving stock (Bounded,Enum)

data KerberosPortField
  = KerberosIdOrigPort
  | KerberosIdRespPort
  deriving stock (Bounded,Enum)

-- This is used for both UIDs and IP addresses.
data KerberosWord128Field
  = KerberosIdOrigHost
  | KerberosIdRespHost
  | KerberosClientCertFuid
  | KerberosServerCertFuid
  | KerberosUid
  deriving stock (Bounded,Enum)

data KerberosTimeField
  = KerberosTimestamp -- From the field named @ts@
  | KerberosFrom
  | KerberosTill
  deriving stock (Bounded,Enum)

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
  = Lexing JsonTokenizeException
  | Parsing ZeekParsingException
  deriving stock (Eq,Show)

data ZeekParsingException
  = IncompleteObject
  | InvalidAuthTicket
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
  | InvalidObjectSeparator
  | InvalidRenewable
  | InvalidRequestType
  | InvalidServer
  | InvalidServerCertFuid
  | InvalidServerCertSubject
  | InvalidService
  | InvalidSuccess
  | InvalidTill
  | InvalidTimestamp
  | InvalidUid
  | MissingIdOrigHost
  | MissingIdOrigPort
  | MissingIdRespHost
  | MissingIdRespPort
  | MissingUid
  | MissingTimestamp
  | NotObject
  deriving stock (Eq,Show)
  

totalKerberosTexts :: Int
totalKerberosTexts =
  1 + fromEnum (maxBound :: KerberosTextField) - fromEnum (minBound :: KerberosTextField)

totalKerberosBools :: Int
totalKerberosBools =
  1 + fromEnum (maxBound :: KerberosBoolField) - fromEnum (minBound :: KerberosBoolField)

totalKerberosTimes :: Int
totalKerberosTimes =
  1 + fromEnum (maxBound :: KerberosTimeField) - fromEnum (minBound :: KerberosTimeField)

totalKerberosPorts :: Int
totalKerberosPorts =
  1 + fromEnum (maxBound :: KerberosPortField) - fromEnum (minBound :: KerberosPortField)

totalKerberosWord128s :: Int
totalKerberosWord128s =
  1 + fromEnum (maxBound :: KerberosWord128Field) - fromEnum (minBound :: KerberosWord128Field)

offsetKerberosTexts :: Int
offsetKerberosTexts = 0

offsetKerberosBools :: Int
offsetKerberosBools = offsetKerberosTexts + totalKerberosTexts

offsetKerberosTimes :: Int
offsetKerberosTimes = offsetKerberosBools + totalKerberosBools

offsetKerberosPorts :: Int
offsetKerberosPorts = offsetKerberosTimes + totalKerberosTimes

offsetKerberosWord128s :: Int
offsetKerberosWord128s = offsetKerberosPorts + totalKerberosPorts

errorThunk :: a
{-# noinline errorThunk #-}
errorThunk = error "Zeek.Json: mistake was made"

decode :: Bytes -> Either ZeekException (Chunks Attribute)
decode b = case J.decode b of
  Left e -> Left (Lexing e)
  Right tokens -> case P.parse parserAttributes tokens of
    P.Success k _ _ -> Right k
    P.Failure e -> Left (Parsing e)

parserAttributes :: Parser Token ZeekParsingException s (Chunks Attribute)
parserAttributes = do
  P.token NotObject J.LeftBrace
  bdr <- P.foldSepBy1
    ( P.any IncompleteObject >>= \case
        J.Comma -> pure True
        J.RightBrace -> pure False
        _ -> P.fail InvalidObjectSeparator
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
  Right tokens -> case P.parse parserKerberos tokens of
    P.Success k _ _ -> Right k
    P.Failure e -> Left (Parsing e)

newKerberosScratchPad :: ST s (Scratchpad s)
newKerberosScratchPad = do
  texts' <- PM.newUnliftedArray totalKerberosTexts (mempty :: ByteArray)
  bools <- PM.newPrimArray totalKerberosBools
  times <- PM.newSmallArray totalKerberosTimes errorThunk
  ports <- PM.newPrimArray totalKerberosPorts
  word128s <- PM.newPrimArray totalKerberosWord128s
  let totalKerberosWrites = 0
        + totalKerberosTexts
        + totalKerberosBools
        + totalKerberosTimes
        + totalKerberosPorts
        + totalKerberosWord128s
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
        _ -> P.fail InvalidObjectSeparator
    )
    (do key <- string InvalidObjectKey
        P.token InvalidObjectPair J.Colon
        kerberosValue scratchpad key
    )
  -- Mandatory Fields
  id_orig_p <- P.effect (readKerberosPort ports writes KerberosIdOrigPort)
    >>= MW16.maybe (P.fail MissingIdOrigPort) pure
  id_resp_p <- P.effect (readKerberosPort ports writes KerberosIdRespPort)
    >>= MW16.maybe (P.fail MissingIdRespPort) pure
  id_orig_h <- P.effect (readKerberosWord128 word128s writes KerberosIdOrigHost)
    >>= MW128.maybe (P.fail MissingIdOrigHost) (pure . IP . IPv6)
  id_resp_h <- P.effect (readKerberosWord128 word128s writes KerberosIdRespHost)
    >>= MW128.maybe (P.fail MissingIdRespHost) (pure . IP . IPv6)
  uid <- P.effect (readKerberosWord128 word128s writes KerberosUid)
    >>= MW128.maybe (P.fail MissingUid) pure
  ts <- P.effect (readKerberosTime times writes KerberosTimestamp)
    >>= M.maybe (P.fail MissingTimestamp) pure
  -- Optional Fields
  P.effect $ do
    auth_ticket <- readKerberosText texts writes KerberosAuthTicket
    cipher <- readKerberosText texts writes KerberosCipher
    client <- readKerberosText texts writes KerberosClient
    client_cert_subject <- readKerberosText texts writes KerberosClientCertSubject
    server_cert_subject <- readKerberosText texts writes KerberosServerCertSubject
    forwardable <- readKerberosBool bools writes KerberosForwardable
    success <- readKerberosBool bools writes KerberosSuccess
    renewable <- readKerberosBool bools writes KerberosRenewable
    request_type <- readKerberosText texts writes KerberosRequestType
    service <- readKerberosText texts writes KerberosService
    error_msg <- readKerberosText texts writes KerberosErrorMessage
    new_ticket <- readKerberosText texts writes KerberosNewTicket
    till <- readKerberosTime times writes KerberosTill
    from <- readKerberosTime times writes KerberosFrom
    client_cert_fuid <- readKerberosWord128 word128s writes KerberosClientCertFuid
    server_cert_fuid <- readKerberosWord128 word128s writes KerberosServerCertFuid
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

-- This currently only handles ipv4 addresses. Fix this.
ip :: e -> Parser Token e s Word128
ip e = P.any e >>= \case
  J.String str -> case IPv4.decodeShort str of
    Nothing -> P.fail e
    Just addr -> case IP.fromIPv4 addr of
      IP (IPv6 w) -> pure w
  _ -> P.fail e

word16 :: e -> Parser Token e s Word16
word16 e = do
  n <- P.any e
  case JN.toWord16 n of
    Nothing -> P.fail e
    Just w -> pure w

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
  'u' -> case len of
    03 -> if | eqShortTextAddr key "uid"# ->
                 uidAttr Uid InvalidUid bdr
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
  'a' -> case len of
    11 -> if | eqShortTextAddr key "auth_ticket"# ->
                 stringAttr AuthTicket InvalidAuthTicket bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    _ -> bdr <$ P.any IncompleteObject
  's' -> case len of
    07 -> if | eqShortTextAddr key "service"# ->
                 stringAttr Service InvalidService bdr
             | eqShortTextAddr key "success"# ->
                 boolAttr Success InvalidSuccess bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    _ -> bdr <$ P.any IncompleteObject
  'r' -> case len of
    09 -> if | eqShortTextAddr key "renewable"# ->
                 boolAttr Renewable InvalidRenewable bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    12 -> if | eqShortTextAddr key "request_type"# ->
                 stringAttr RequestType InvalidRequestType bdr
             | otherwise -> bdr <$ P.any IncompleteObject
    _ -> bdr <$ P.any IncompleteObject
  'f' -> case len of
    11 -> if | eqShortTextAddr key "forwardable"# ->
                 boolAttr Forwardable InvalidForwardable bdr
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

portAttr ::
     PortField
  -> ZeekParsingException
  -> Builder.Builder s Attribute
  -> Parser Token ZeekParsingException s (Builder.Builder s Attribute)
portAttr field err bdr = do
  str <- word16 err
  let !attr = PortAttribute field str
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
                  >>= P.effect . writeKerberosText texts writes KerberosAuthTicket
            | otherwise -> () <$ P.any IncompleteObject
  'e' -> if | eqShortTextAddr key "error_msg"# ->
                string InvalidErrorMessage
                  >>= P.effect . writeKerberosText texts writes KerberosErrorMessage
            | otherwise -> () <$ P.any IncompleteObject
  'n' -> if | eqShortTextAddr key "new_ticket"# ->
                string InvalidNewTicket
                  >>= P.effect . writeKerberosText texts writes KerberosNewTicket
            | otherwise -> () <$ P.any IncompleteObject
  'f' -> if | eqShortTextAddr key "forwardable"# ->
                boolean InvalidForwardable
                  >>= P.effect . writeKerberosBool bools writes KerberosForwardable
            | eqShortTextAddr key "from"# ->
                timeToken InvalidFrom
                  >>= P.effect . writeKerberosTime times writes KerberosFrom
            | otherwise -> () <$ P.any IncompleteObject
  'r' -> if | eqShortTextAddr key "renewable"# ->
                boolean InvalidRenewable
                  >>= P.effect . writeKerberosBool bools writes KerberosRenewable
            | eqShortTextAddr key "request_type"# ->
                string InvalidRequestType
                  >>= P.effect . writeKerberosText texts writes KerberosRequestType
            | otherwise -> () <$ P.any IncompleteObject
  'i' -> if | eqShortTextAddr key "id.orig_p"# ->
                word16 InvalidIdOrigPort
                  >>= P.effect . writeKerberosPort ports writes KerberosIdOrigPort
            | eqShortTextAddr key "id.resp_p"# ->
                word16 InvalidIdRespPort
                  >>= P.effect . writeKerberosPort ports writes KerberosIdRespPort
            | eqShortTextAddr key "id.orig_h"# ->
                ip InvalidIdOrigHost
                  >>= P.effect . writeKerberosWord128 word128s writes KerberosIdOrigHost
            | eqShortTextAddr key "id.resp_h"# ->
                ip InvalidIdRespHost
                  >>= P.effect . writeKerberosWord128 word128s writes KerberosIdRespHost
            | otherwise -> () <$ P.any IncompleteObject
  'u' -> if | eqShortTextAddr key "uid"# ->
                uidToken InvalidUid
                  >>= P.effect . writeKerberosWord128 word128s writes KerberosUid
            | otherwise -> () <$ P.any IncompleteObject
  'c' -> if | eqShortTextAddr key "cipher"# ->
                string InvalidCipher
                  >>= P.effect . writeKerberosText texts writes KerberosCipher
            | eqShortTextAddr key "client"# ->
                string InvalidClient
                  >>= P.effect . writeKerberosText texts writes KerberosClient
            | eqShortTextAddr key "client_cert_subject"# ->
                string InvalidClientCertSubject
                  >>= P.effect . writeKerberosText texts writes KerberosClientCertSubject
            | eqShortTextAddr key "server_cert_fuid"# ->
                uidToken InvalidClientCertFuid
                  >>= P.effect . writeKerberosWord128 word128s writes KerberosClientCertFuid
            | otherwise -> () <$ P.any IncompleteObject
  's' -> if | eqShortTextAddr key "success"# ->
                boolean InvalidSuccess
                  >>= P.effect . writeKerberosBool bools writes KerberosSuccess
            | eqShortTextAddr key "service"# ->
                string InvalidService
                  >>= P.effect . writeKerberosText texts writes KerberosService
            | eqShortTextAddr key "server_cert_subject"# ->
                string InvalidServerCertSubject
                  >>= P.effect . writeKerberosText texts writes KerberosServerCertSubject
            | eqShortTextAddr key "server_cert_fuid"# ->
                uidToken InvalidServerCertFuid
                  >>= P.effect . writeKerberosWord128 word128s writes KerberosServerCertFuid
            | otherwise -> () <$ P.any IncompleteObject
  't' -> if | eqShortTextAddr key "ts"# ->
                timeToken InvalidTimestamp
                  >>= P.effect . writeKerberosTime times writes KerberosTimestamp
            | eqShortTextAddr key "till"# ->
                timeToken InvalidTill
                  >>= P.effect . writeKerberosTime times writes KerberosTill
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
readKerberosText marr writes field = do
  PM.readPrimArray writes (fromEnum field + offsetKerberosTexts) >>= \case
    1 -> fmap TSM.just (readTextArray marr (fromEnum field))
    _ -> pure TSM.nothing

readKerberosTime ::
     SmallMutableArray s Datetime
  -> MutablePrimArray s Word8
  -> KerberosTimeField
  -> ST s (M.Maybe Datetime)
readKerberosTime marr writes field = do
  PM.readPrimArray writes (fromEnum field + offsetKerberosTimes) >>= \case
    1 -> fmap M.just (PM.readSmallArray marr (fromEnum field))
    _ -> pure M.nothing

readKerberosPort ::
     MutablePrimArray s Word16
  -> MutablePrimArray s Word8
  -> KerberosPortField
  -> ST s MW16.Maybe
readKerberosPort marr writes field = do
  PM.readPrimArray writes (fromEnum field + offsetKerberosPorts) >>= \case
    1 -> fmap MW16.just (PM.readPrimArray marr (fromEnum field))
    _ -> pure MW16.nothing

readKerberosWord128 ::
     MutablePrimArray s Word128
  -> MutablePrimArray s Word8
  -> KerberosWord128Field
  -> ST s MW128.Maybe
readKerberosWord128 marr writes field = do
  PM.readPrimArray writes (fromEnum field + offsetKerberosWord128s) >>= \case
    1 -> fmap MW128.just (PM.readPrimArray marr (fromEnum field))
    _ -> pure MW128.nothing


readKerberosBool ::
     MutablePrimArray s Word8
  -> MutablePrimArray s Word8
  -> KerberosBoolField
  -> ST s (M.Maybe Bool)
readKerberosBool marr writes field = do
  PM.readPrimArray writes (fromEnum field + offsetKerberosBools) >>= \case
    1 -> do
      PM.readPrimArray marr (fromEnum field) >>= \case
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
  let !ix = fromEnum field
  writeTextArray marr ix str
  PM.writePrimArray writes (ix + offsetKerberosTexts) (1 :: Word8)

writeKerberosTime ::
     SmallMutableArray s Datetime -- array of texts
  -> MutablePrimArray s Word8 -- array to track writes
  -> KerberosTimeField
  -> Datetime
  -> ST s ()
writeKerberosTime marr writes field time = do
  let !ix = fromEnum field
  PM.writeSmallArray marr ix time
  PM.writePrimArray writes (ix + offsetKerberosTimes) (1 :: Word8)

writeKerberosPort ::
     MutablePrimArray s Word16 -- array of ports
  -> MutablePrimArray s Word8 -- array to track writes
  -> KerberosPortField
  -> Word16
  -> ST s ()
writeKerberosPort marr writes field w = do
  let !ix = fromEnum field
  PM.writePrimArray marr ix w
  PM.writePrimArray writes (ix + offsetKerberosPorts) (1 :: Word8)

writeKerberosWord128 ::
     MutablePrimArray s Word128 -- array of ports
  -> MutablePrimArray s Word8 -- array to track writes
  -> KerberosWord128Field
  -> Word128
  -> ST s ()
writeKerberosWord128 marr writes field w = do
  let !ix = fromEnum field
  PM.writePrimArray marr ix w
  PM.writePrimArray writes (ix + offsetKerberosWord128s) (1 :: Word8)

writeKerberosBool ::
     MutablePrimArray s Word8 -- array of bools
  -> MutablePrimArray s Word8 -- array to track writes
  -> KerberosBoolField
  -> Bool
  -> ST s ()
writeKerberosBool marr writes field b = do
  let !ix = fromEnum field
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
  BP.Success datetime _ remaining -> case remaining of
    0 -> Just datetime
    _ -> Nothing
  BP.Failure _ -> Nothing

parserDatetime :: BP.Parser () s Datetime
parserDatetime = do
  year <- BP.decWord16 ()
  BP.ascii () '-'
  month0 <- BP.decWord8 ()
  let month1 = fromIntegral @Word8 @Word8 month0 - 1
  when (month1 >= 12) (BP.fail ())
  BP.ascii () '-'
  day <- BP.decWord8 ()
  BP.ascii () 'T'
  hour <- BP.decWord8 ()
  when (hour >= 24) (BP.fail ())
  BP.ascii () ':'
  minute <- BP.decWord8 ()
  when (minute >= 60) (BP.fail ())
  BP.ascii () ':'
  second <- BP.decWord8 ()
  when (second >= 60) (BP.fail ())
  BP.ascii () '.'
  microsecond <- BP.decWord32 ()
  when (microsecond >= 1000000) (BP.fail ())
  BP.ascii () 'Z'
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
