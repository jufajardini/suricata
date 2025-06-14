/* Copyright (C) 2007-2024 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef SURICATA_DETECT_ENGINE_REGISTER_H
#define SURICATA_DETECT_ENGINE_REGISTER_H

enum DetectKeywordId {
    DETECT_SID,
    DETECT_PRIORITY,
    DETECT_REV,
    DETECT_CLASSTYPE,

    /* sorted by prefilter priority. Higher in this list means it will be
     * picked over ones lower in the list */
    DETECT_APP_LAYER_PROTOCOL,
    DETECT_ACK,
    DETECT_SEQ,
    DETECT_WINDOW,
    DETECT_IPOPTS,
    DETECT_IPADDR_SRC,
    DETECT_IPADDR_DST,
    DETECT_FLAGS,
    DETECT_FRAGBITS,
    DETECT_FRAGOFFSET,
    DETECT_TTL,
    DETECT_TOS,
    DETECT_ITYPE,
    DETECT_ICODE,
    DETECT_ICMP_ID,
    DETECT_ICMP_SEQ,
    DETECT_ICMPV4HDR,
    DETECT_DSIZE,

    DETECT_FLOW,
    /* end prefilter sort */

    /* values used in util-var.c go here, to avoid int overflows */
    DETECT_THRESHOLD,
    DETECT_FLOWBITS,
    DETECT_FLOWVAR,
    DETECT_FLOWVAR_POSTMATCH,
    DETECT_FLOWINT,
    DETECT_HOSTBITS,
    DETECT_XBITS,
    DETECT_PKTVAR,
    /* end util-var.c logic */

    /* content inspection */
    DETECT_CONTENT,
    DETECT_URICONTENT,
    DETECT_PCRE,
    DETECT_DEPTH,
    DETECT_STARTS_WITH,
    DETECT_ENDS_WITH,
    DETECT_DISTANCE,
    DETECT_WITHIN,
    DETECT_OFFSET,
    DETECT_REPLACE,
    DETECT_NOCASE,
    DETECT_FAST_PATTERN,
    DETECT_RAWBYTES,
    DETECT_BYTETEST,
    DETECT_BYTEJUMP,
    DETECT_BYTEMATH,
    DETECT_BYTE_EXTRACT,
    DETECT_DATASET,
    DETECT_DATAREP,
    DETECT_BASE64_DECODE,
    DETECT_BASE64_DATA,
    DETECT_BSIZE,
    DETECT_ASN1,
    DETECT_LUA,
    DETECT_ISDATAAT,
    DETECT_URILEN,
    DETECT_ABSENT,
    DETECT_ENTROPY,
    /* end of content inspection */

    DETECT_METADATA,
    DETECT_REFERENCE,
    DETECT_TAG,
    DETECT_MSG,
    DETECT_SAMEIP,
    DETECT_GEOIP,
    DETECT_IPPROTO,
    DETECT_FTPBOUNCE,
    DETECT_FTP_DYNPORT,
    DETECT_ID,
    DETECT_RPC,
    DETECT_NOALERT,
    DETECT_ALERT,
    DETECT_IPV4_CSUM,
    DETECT_TCPV4_CSUM,
    DETECT_TCPV6_CSUM,
    DETECT_UDPV4_CSUM,
    DETECT_UDPV6_CSUM,
    DETECT_ICMPV4_CSUM,
    DETECT_ICMPV6_CSUM,
    DETECT_STREAM_SIZE,
    DETECT_DETECTION_FILTER,

    DETECT_DECODE_EVENT,
    DETECT_GID,
    DETECT_MARK,

    DETECT_FRAME,

    DETECT_FLOW_AGE,
    DETECT_FLOW_PKTS,
    DETECT_FLOW_PKTS_TO_SERVER,
    DETECT_FLOW_PKTS_TO_CLIENT,
    DETECT_FLOW_BYTES,
    DETECT_FLOW_BYTES_TO_SERVER,
    DETECT_FLOW_BYTES_TO_CLIENT,

    DETECT_REQUIRES,

    DETECT_TLS_VERSION,
    DETECT_TLS_SUBJECT,
    DETECT_TLS_ISSUERDN,
    DETECT_TLS_NOTBEFORE,
    DETECT_TLS_NOTAFTER,
    DETECT_TLS_EXPIRED,
    DETECT_TLS_VALID,
    DETECT_TLS_FINGERPRINT,
    DETECT_TLS_STORE,
    DETECT_TLS_CHAIN_LEN,
    DETECT_TLS_ALPN,

    DETECT_HTTP_COOKIE_CM,
    DETECT_HTTP_COOKIE,
    DETECT_HTTP_METHOD_CM,
    DETECT_HTTP_METHOD,
    DETECT_HTTP_PROTOCOL,
    DETECT_HTTP_START,
    DETECT_HTTP_CLIENT_BODY,
    DETECT_HTTP_REQUEST_BODY,
    DETECT_HTTP_SERVER_BODY,
    DETECT_HTTP_RESPONSE_BODY,
    DETECT_HTTP_HEADER_CM,
    DETECT_HTTP_HEADER,
    DETECT_HTTP_HEADER_NAMES,
    DETECT_HTTP_HEADER_ACCEPT,
    DETECT_HTTP_HEADER_ACCEPT_LANG,
    DETECT_HTTP_HEADER_ACCEPT_ENC,
    DETECT_HTTP_HEADER_CONNECTION,
    DETECT_HTTP_HEADER_CONTENT_LEN,
    DETECT_HTTP_HEADER_CONTENT_TYPE,
    DETECT_HTTP_HEADER_LOCATION,
    DETECT_HTTP_HEADER_SERVER,
    DETECT_HTTP_HEADER_REFERER,
    DETECT_HTTP_RAW_HEADER_CM,
    DETECT_HTTP_RAW_HEADER,
    DETECT_HTTP_URI_CM,
    DETECT_HTTP_URI,
    DETECT_HTTP_URI_RAW,
    DETECT_HTTP_RAW_URI,
    DETECT_HTTP_STAT_MSG_CM,
    DETECT_HTTP_STAT_MSG,
    DETECT_HTTP_STAT_CODE_CM,
    DETECT_HTTP_STAT_CODE,
    DETECT_HTTP_USER_AGENT,
    DETECT_HTTP_UA,
    DETECT_HTTP_HOST_CM,
    DETECT_HTTP_HOST,
    DETECT_HTTP_RAW_HOST,
    DETECT_HTTP_HOST_RAW,
    DETECT_HTTP_REQUEST_LINE,
    DETECT_HTTP_RESPONSE_LINE,
    DETECT_NFS_PROCEDURE,
    DETECT_NFS_VERSION,
    DETECT_SSH_PROTOCOL,
    DETECT_SSH_PROTOVERSION,
    DETECT_SSH_SOFTWARE,
    DETECT_SSH_SOFTWAREVERSION,
    DETECT_SSH_HASSH,
    DETECT_SSH_HASSH_SERVER,
    DETECT_SSH_HASSH_STRING,
    DETECT_SSH_HASSH_SERVER_STRING,
    DETECT_SSL_VERSION,
    DETECT_SSL_STATE,
    DETECT_FILE_DATA,
    DETECT_PKT_DATA,
    DETECT_APP_LAYER_EVENT,
    DETECT_APP_LAYER_STATE,

    DETECT_HTTP2_FRAMETYPE,
    DETECT_HTTP2_ERRORCODE,
    DETECT_HTTP2_PRIORITY,
    DETECT_HTTP2_WINDOW,
    DETECT_HTTP2_SIZEUPDATE,
    DETECT_HTTP2_SETTINGS,
    DETECT_HTTP2_HEADERNAME,
    DETECT_HTTP_REQUEST_HEADER,
    DETECT_HTTP_RESPONSE_HEADER,

    DETECT_DCE_IFACE,
    DETECT_DCE_OPNUM,
    DETECT_DCE_STUB_DATA,
    DETECT_SMB_NAMED_PIPE,
    DETECT_SMB_SHARE,
    DETECT_SMB_NTLMSSP_USER,
    DETECT_SMB_NTLMSSP_DOMAIN,
    DETECT_SMB_VERSION,

    DETECT_ENGINE_EVENT,
    DETECT_STREAM_EVENT,

    DETECT_CONFIG,

    DETECT_FILENAME,
    DETECT_FILE_NAME,
    DETECT_FILEEXT,
    DETECT_FILESTORE,
    DETECT_FILESTORE_POSTMATCH,
    DETECT_FILEMAGIC,
    DETECT_FILE_MAGIC,
    DETECT_FILEMD5,
    DETECT_FILESHA1,
    DETECT_FILESHA256,
    DETECT_FILESIZE,

    DETECT_L3PROTO,
    DETECT_IPREP,

    DETECT_DNS_RESPONSE,
    DETECT_TLS_SNI,
    DETECT_TLS_CERTS,
    DETECT_TLS_CERT_ISSUER,
    DETECT_TLS_CERT_SUBJECT,
    DETECT_TLS_CERT_SERIAL,
    DETECT_TLS_CERT_FINGERPRINT,
    DETECT_TLS_SUBJECTALTNAME,
    DETECT_TLS_RANDOM_TIME,
    DETECT_TLS_RANDOM_BYTES,
    DETECT_TLS_RANDOM,

    DETECT_TLS_JA3_HASH,
    DETECT_TLS_JA3_STRING,
    DETECT_TLS_JA3S_HASH,
    DETECT_TLS_JA3S_STRING,

    DETECT_MODBUS,

    DETECT_DNP3DATA,
    DETECT_DNP3FUNC,
    DETECT_DNP3IND,
    DETECT_DNP3OBJ,

    DETECT_KRB5_ERRCODE,
    DETECT_KRB5_MSGTYPE,
    DETECT_KRB5_CNAME,
    DETECT_KRB5_SNAME,
    DETECT_KRB5_TICKET_ENCRYPTION,

    DETECT_SIP_METHOD,
    DETECT_SIP_URI,
    DETECT_SIP_PROTOCOL,
    DETECT_SIP_STAT_CODE,
    DETECT_SIP_STAT_MSG,
    DETECT_SIP_REQUEST_LINE,
    DETECT_SIP_RESPONSE_LINE,
    DETECT_TEMPLATE,
    DETECT_TEMPLATE2,
    DETECT_IPV4HDR,
    DETECT_IPV6HDR,
    DETECT_ICMPV6HDR,
    DETECT_ICMPV6MTU,
    DETECT_TCPHDR,
    DETECT_UDPHDR,
    DETECT_TCPMSS,
    DETECT_TCP_WSCALE,
    DETECT_FTPDATA,
    DETECT_TARGET,
    DETECT_QUIC_VERSION,
    DETECT_QUIC_SNI,
    DETECT_QUIC_UA,
    DETECT_QUIC_CYU_HASH,
    DETECT_QUIC_CYU_STRING,

    DETECT_BYPASS,

    DETECT_PREFILTER,

    DETECT_TRANSFORM_PCREXFORM,
    DETECT_TRANSFORM_LUAXFORM,

    DETECT_IKE_EXCH_TYPE,
    DETECT_IKE_SPI_INITIATOR,
    DETECT_IKE_SPI_RESPONDER,
    DETECT_IKE_VENDOR,
    DETECT_IKE_CHOSEN_SA,
    DETECT_IKE_KEY_EXCHANGE_PAYLOAD_LENGTH,
    DETECT_IKE_NONCE_PAYLOAD_LENGTH,
    DETECT_IKE_NONCE,
    DETECT_IKE_KEY_EXCHANGE,

    DETECT_JA4_HASH,

    DETECT_FTP_COMMAND,
    DETECT_FTP_COMMAND_DATA,
    DETECT_FTP_REPLY,
    DETECT_FTP_MODE,
    DETECT_FTP_REPLY_RECEIVED,
    DETECT_FTP_COMPLETION_CODE,

    DETECT_VLAN_ID,
    DETECT_VLAN_LAYERS,

    /* make sure this stays last */
    DETECT_TBLSIZE_STATIC,
};

extern int DETECT_TBLSIZE;
extern int DETECT_TBLSIZE_IDX;
// step for reallocating sigmatch_table
#define DETECT_TBLSIZE_STEP 256
int SigTableList(const char *keyword);
void SigTableCleanup(void);
void SigTableInit(void);
void SigTableSetup(void);
int SCSigTablePreRegister(void (*KeywordsRegister)(void));
void SigTableRegisterTests(void);
bool SigTableHasKeyword(const char *keyword);
void SCDetectHelperKeywordSetCleanCString(uint16_t id);

#endif /* SURICATA_DETECT_ENGINE_REGISTER_H */
