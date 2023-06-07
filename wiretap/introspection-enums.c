/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Generated automatically from make-enums.py. It can be re-created by running
 * "tools/make-enums.py" from the top source directory.
 *
 * It is fine to edit this file by hand. Particularly if a symbol
 * disappears from the API it can just be removed here. There is no
 * requirement to re-run the generator script.
 *
 */
#include <wiretap/wtap.h>

#define ENUM(arg) { #arg, arg }

static ws_enum_t all_enums[] = {
    ENUM(AAL_1),
    ENUM(AAL_2),
    ENUM(AAL_3_4),
    ENUM(AAL_5),
    ENUM(AAL_OAMCELL),
    ENUM(AAL_SIGNALLING),
    ENUM(AAL_UNKNOWN),
    ENUM(AAL_USER),
    ENUM(ASCEND_MAX_STR_LEN),
    ENUM(ASCEND_PFX_ETHER),
    ENUM(ASCEND_PFX_ISDN_R),
    ENUM(ASCEND_PFX_ISDN_X),
    ENUM(ASCEND_PFX_WDD),
    ENUM(ASCEND_PFX_WDS_R),
    ENUM(ASCEND_PFX_WDS_X),
    ENUM(ATM_AAL2_NOPHDR),
    ENUM(ATM_NO_HEC),
    ENUM(ATM_RAW_CELL),
    ENUM(ATM_REASSEMBLY_ERROR),
    ENUM(BBLOG_TYPE_EVENT_BLOCK),
    ENUM(BBLOG_TYPE_SKIPPED_BLOCK),
    ENUM(BLOCK_NOT_SUPPORTED),
    ENUM(BTHCI_CHANNEL_ACL),
    ENUM(BTHCI_CHANNEL_COMMAND),
    ENUM(BTHCI_CHANNEL_EVENT),
    ENUM(BTHCI_CHANNEL_ISO),
    ENUM(BTHCI_CHANNEL_SCO),
    ENUM(COSINE_DIR_RX),
    ENUM(COSINE_DIR_TX),
    ENUM(COSINE_ENCAP_ATM),
    ENUM(COSINE_ENCAP_ETH),
    ENUM(COSINE_ENCAP_FR),
    ENUM(COSINE_ENCAP_HDLC),
    ENUM(COSINE_ENCAP_PPP),
    ENUM(COSINE_ENCAP_PPoATM),
    ENUM(COSINE_ENCAP_PPoFR),
    ENUM(COSINE_ENCAP_TEST),
    ENUM(COSINE_ENCAP_UNKNOWN),
    ENUM(COSINE_MAX_IF_NAME_LEN),
    ENUM(FROM_DCE),
    ENUM(FT_SORT_BY_DESCRIPTION),
    ENUM(FT_SORT_BY_NAME),
    ENUM(GSM_UM_CHANNEL_AGCH),
    ENUM(GSM_UM_CHANNEL_BCCH),
    ENUM(GSM_UM_CHANNEL_CCCH),
    ENUM(GSM_UM_CHANNEL_FACCH),
    ENUM(GSM_UM_CHANNEL_PCH),
    ENUM(GSM_UM_CHANNEL_RACH),
    ENUM(GSM_UM_CHANNEL_SACCH),
    ENUM(GSM_UM_CHANNEL_SDCCH),
    ENUM(GSM_UM_CHANNEL_UNKNOWN),
    ENUM(IRDA_CLASS_FRAME),
    ENUM(IRDA_CLASS_LOG),
    ENUM(IRDA_CLASS_MASK),
    ENUM(IRDA_INCOMING),
    ENUM(IRDA_LOG_MESSAGE),
    ENUM(IRDA_MISSED_MSG),
    ENUM(IRDA_OUTGOING),
    ENUM(K12_PORT_ATMPVC),
    ENUM(K12_PORT_DS0S),
    ENUM(K12_PORT_DS1),
    ENUM(LLCP_PHDR_FLAG_SENT),
    ENUM(MAXNAMELEN),
    ENUM(MAX_ERF_EHDR),
    ENUM(MTP2_ANNEX_A_NOT_USED),
    ENUM(MTP2_ANNEX_A_USED),
    ENUM(MTP2_ANNEX_A_USED_UNKNOWN),
    ENUM(MULTIPLE_BLOCKS_SUPPORTED),
    ENUM(MULTIPLE_OPTIONS_SUPPORTED),
    ENUM(ONE_BLOCK_SUPPORTED),
    ENUM(ONE_OPTION_SUPPORTED),
    ENUM(OPEN_INFO_HEURISTIC),
    ENUM(OPEN_INFO_MAGIC),
    ENUM(OPTION_NOT_SUPPORTED),
    ENUM(PACK_FLAGS_CRC_ERROR),
    ENUM(PACK_FLAGS_DIRECTION_INBOUND),
    ENUM(PACK_FLAGS_DIRECTION_MASK),
    ENUM(PACK_FLAGS_DIRECTION_OUTBOUND),
    ENUM(PACK_FLAGS_DIRECTION_SHIFT),
    ENUM(PACK_FLAGS_DIRECTION_UNKNOWN),
    ENUM(PACK_FLAGS_FCS_LENGTH_MASK),
    ENUM(PACK_FLAGS_FCS_LENGTH_SHIFT),
    ENUM(PACK_FLAGS_PACKET_TOO_LONG),
    ENUM(PACK_FLAGS_PACKET_TOO_SHORT),
    ENUM(PACK_FLAGS_PREAMBLE_ERROR),
    ENUM(PACK_FLAGS_RECEPTION_TYPE_BROADCAST),
    ENUM(PACK_FLAGS_RECEPTION_TYPE_MASK),
    ENUM(PACK_FLAGS_RECEPTION_TYPE_MULTICAST),
    ENUM(PACK_FLAGS_RECEPTION_TYPE_PROMISCUOUS),
    ENUM(PACK_FLAGS_RECEPTION_TYPE_SHIFT),
    ENUM(PACK_FLAGS_RECEPTION_TYPE_UNICAST),
    ENUM(PACK_FLAGS_RECEPTION_TYPE_UNSPECIFIED),
    ENUM(PACK_FLAGS_RESERVED_MASK),
    ENUM(PACK_FLAGS_START_FRAME_DELIMITER_ERROR),
    ENUM(PACK_FLAGS_SYMBOL_ERROR),
    ENUM(PACK_FLAGS_UNALIGNED_FRAME),
    ENUM(PACK_FLAGS_WRONG_INTER_FRAME_GAP),
    ENUM(PHDR_802_11AD_MAX_FREQUENCY),
    ENUM(PHDR_802_11AD_MIN_FREQUENCY),
    ENUM(PHDR_802_11A_CHANNEL_TYPE_HALF_CLOCKED),
    ENUM(PHDR_802_11A_CHANNEL_TYPE_NORMAL),
    ENUM(PHDR_802_11A_CHANNEL_TYPE_QUARTER_CLOCKED),
    ENUM(PHDR_802_11A_TURBO_TYPE_DYNAMIC_TURBO),
    ENUM(PHDR_802_11A_TURBO_TYPE_NORMAL),
    ENUM(PHDR_802_11A_TURBO_TYPE_STATIC_TURBO),
    ENUM(PHDR_802_11A_TURBO_TYPE_TURBO),
    ENUM(PHDR_802_11G_MODE_NORMAL),
    ENUM(PHDR_802_11G_MODE_SUPER_G),
    ENUM(PHDR_802_11_0_LENGTH_PSDU_S1G_NDP),
    ENUM(PHDR_802_11_0_LENGTH_PSDU_VENDOR_SPECIFIC),
    ENUM(PHDR_802_11_A_MPDU_DELIM_CRC_ERROR),
    ENUM(PHDR_802_11_BANDWIDTH_160_MHZ),
    ENUM(PHDR_802_11_BANDWIDTH_20LL),
    ENUM(PHDR_802_11_BANDWIDTH_20LLL),
    ENUM(PHDR_802_11_BANDWIDTH_20LLU),
    ENUM(PHDR_802_11_BANDWIDTH_20LU),
    ENUM(PHDR_802_11_BANDWIDTH_20LUL),
    ENUM(PHDR_802_11_BANDWIDTH_20LUU),
    ENUM(PHDR_802_11_BANDWIDTH_20UL),
    ENUM(PHDR_802_11_BANDWIDTH_20ULL),
    ENUM(PHDR_802_11_BANDWIDTH_20ULU),
    ENUM(PHDR_802_11_BANDWIDTH_20UU),
    ENUM(PHDR_802_11_BANDWIDTH_20UUL),
    ENUM(PHDR_802_11_BANDWIDTH_20UUU),
    ENUM(PHDR_802_11_BANDWIDTH_20_20L),
    ENUM(PHDR_802_11_BANDWIDTH_20_20U),
    ENUM(PHDR_802_11_BANDWIDTH_20_MHZ),
    ENUM(PHDR_802_11_BANDWIDTH_40LL),
    ENUM(PHDR_802_11_BANDWIDTH_40LU),
    ENUM(PHDR_802_11_BANDWIDTH_40UL),
    ENUM(PHDR_802_11_BANDWIDTH_40UU),
    ENUM(PHDR_802_11_BANDWIDTH_40_40L),
    ENUM(PHDR_802_11_BANDWIDTH_40_40U),
    ENUM(PHDR_802_11_BANDWIDTH_40_MHZ),
    ENUM(PHDR_802_11_BANDWIDTH_80_80L),
    ENUM(PHDR_802_11_BANDWIDTH_80_80U),
    ENUM(PHDR_802_11_BANDWIDTH_80_MHZ),
    ENUM(PHDR_802_11_DATA_NOT_CAPTURED),
    ENUM(PHDR_802_11_LAST_PART_OF_A_MPDU),
    ENUM(PHDR_802_11_PHY_11A),
    ENUM(PHDR_802_11_PHY_11AC),
    ENUM(PHDR_802_11_PHY_11AD),
    ENUM(PHDR_802_11_PHY_11AH),
    ENUM(PHDR_802_11_PHY_11AX),
    ENUM(PHDR_802_11_PHY_11B),
    ENUM(PHDR_802_11_PHY_11BE),
    ENUM(PHDR_802_11_PHY_11G),
    ENUM(PHDR_802_11_PHY_11N),
    ENUM(PHDR_802_11_PHY_11_DSSS),
    ENUM(PHDR_802_11_PHY_11_FHSS),
    ENUM(PHDR_802_11_PHY_11_IR),
    ENUM(PHDR_802_11_PHY_UNKNOWN),
    ENUM(PHDR_802_11_SOUNDING_PSDU),
    ENUM(REC_TYPE_CUSTOM_BLOCK),
    ENUM(REC_TYPE_FT_SPECIFIC_EVENT),
    ENUM(REC_TYPE_FT_SPECIFIC_REPORT),
    ENUM(REC_TYPE_PACKET),
    ENUM(REC_TYPE_SYSCALL),
    ENUM(REC_TYPE_SYSTEMD_JOURNAL_EXPORT),
    ENUM(SITA_ERROR_NO_BUFFER),
    ENUM(SITA_ERROR_RX_ABORT),
    ENUM(SITA_ERROR_RX_BREAK),
    ENUM(SITA_ERROR_RX_CD_LOST),
    ENUM(SITA_ERROR_RX_COLLISION),
    ENUM(SITA_ERROR_RX_CRC),
    ENUM(SITA_ERROR_RX_DPLL),
    ENUM(SITA_ERROR_RX_FRAME_LEN_VIOL),
    ENUM(SITA_ERROR_RX_FRAME_LONG),
    ENUM(SITA_ERROR_RX_FRAME_SHORT),
    ENUM(SITA_ERROR_RX_FRAMING),
    ENUM(SITA_ERROR_RX_NONOCTET_ALIGNED),
    ENUM(SITA_ERROR_RX_OVERRUN),
    ENUM(SITA_ERROR_RX_PARITY),
    ENUM(SITA_ERROR_RX_UNDEF1),
    ENUM(SITA_ERROR_RX_UNDEF2),
    ENUM(SITA_ERROR_RX_UNDEF3),
    ENUM(SITA_ERROR_TX_CTS_LOST),
    ENUM(SITA_ERROR_TX_RETX_LIMIT),
    ENUM(SITA_ERROR_TX_UART_ERROR),
    ENUM(SITA_ERROR_TX_UNDEF1),
    ENUM(SITA_ERROR_TX_UNDEF2),
    ENUM(SITA_ERROR_TX_UNDEF3),
    ENUM(SITA_ERROR_TX_UNDEF4),
    ENUM(SITA_ERROR_TX_UNDERRUN),
    ENUM(SITA_FRAME_DIR),
    ENUM(SITA_FRAME_DIR_RXED),
    ENUM(SITA_FRAME_DIR_TXED),
    ENUM(SITA_PROTO_ALC),
    ENUM(SITA_PROTO_ASYNC_BLKIO),
    ENUM(SITA_PROTO_ASYNC_INTIO),
    ENUM(SITA_PROTO_BOP_FRL),
    ENUM(SITA_PROTO_BOP_LAPB),
    ENUM(SITA_PROTO_DPM_LINK),
    ENUM(SITA_PROTO_ETHERNET),
    ENUM(SITA_PROTO_I2C),
    ENUM(SITA_PROTO_PPP_HDLC),
    ENUM(SITA_PROTO_SDLC),
    ENUM(SITA_PROTO_TOKENRING),
    ENUM(SITA_PROTO_UNUSED),
    ENUM(SITA_PROTO_UTS),
    ENUM(SITA_SIG_CTS),
    ENUM(SITA_SIG_DCD),
    ENUM(SITA_SIG_DSR),
    ENUM(SITA_SIG_DTR),
    ENUM(SITA_SIG_RTS),
    ENUM(SITA_SIG_UNDEF1),
    ENUM(SITA_SIG_UNDEF2),
    ENUM(SITA_SIG_UNDEF3),
    ENUM(TRAF_FR),
    ENUM(TRAF_GPRS_NS),
    ENUM(TRAF_ILMI),
    ENUM(TRAF_IPSILON),
    ENUM(TRAF_LANE),
    ENUM(TRAF_LLCMX),
    ENUM(TRAF_SPANS),
    ENUM(TRAF_SSCOP),
    ENUM(TRAF_ST_IPSILON_FT0),
    ENUM(TRAF_ST_IPSILON_FT1),
    ENUM(TRAF_ST_IPSILON_FT2),
    ENUM(TRAF_ST_LANE_802_3),
    ENUM(TRAF_ST_LANE_802_3_MC),
    ENUM(TRAF_ST_LANE_802_5),
    ENUM(TRAF_ST_LANE_802_5_MC),
    ENUM(TRAF_ST_LANE_LE_CTRL),
    ENUM(TRAF_ST_UNKNOWN),
    ENUM(TRAF_ST_VCMX_802_3),
    ENUM(TRAF_ST_VCMX_802_3_FCS),
    ENUM(TRAF_ST_VCMX_802_4),
    ENUM(TRAF_ST_VCMX_802_4_FCS),
    ENUM(TRAF_ST_VCMX_802_5),
    ENUM(TRAF_ST_VCMX_802_5_FCS),
    ENUM(TRAF_ST_VCMX_802_6),
    ENUM(TRAF_ST_VCMX_802_6_FCS),
    ENUM(TRAF_ST_VCMX_BPDU),
    ENUM(TRAF_ST_VCMX_FDDI),
    ENUM(TRAF_ST_VCMX_FDDI_FCS),
    ENUM(TRAF_ST_VCMX_FRAGMENTS),
    ENUM(TRAF_UMTS_FP),
    ENUM(TRAF_UNKNOWN),
    ENUM(TRAF_VCMX),
    ENUM(WTAP_COMMENT_PER_INTERFACE),
    ENUM(WTAP_COMMENT_PER_PACKET),
    ENUM(WTAP_COMMENT_PER_SECTION),
    ENUM(WTAP_ENCAP_3MB_ETHERNET),
    ENUM(WTAP_ENCAP_APPLE_IP_OVER_IEEE1394),
    ENUM(WTAP_ENCAP_ARCNET),
    ENUM(WTAP_ENCAP_ARCNET_LINUX),
    ENUM(WTAP_ENCAP_ASCEND),
    ENUM(WTAP_ENCAP_ATM_PDUS),
    ENUM(WTAP_ENCAP_ATM_PDUS_UNTRUNCATED),
    ENUM(WTAP_ENCAP_ATM_RFC1483),
    ENUM(WTAP_ENCAP_ATSC_ALP),
    ENUM(WTAP_ENCAP_AUERSWALD_LOG),
    ENUM(WTAP_ENCAP_AUTOSAR_DLT),
    ENUM(WTAP_ENCAP_AX25),
    ENUM(WTAP_ENCAP_AX25_KISS),
    ENUM(WTAP_ENCAP_BACNET_MS_TP),
    ENUM(WTAP_ENCAP_BACNET_MS_TP_WITH_PHDR),
    ENUM(WTAP_ENCAP_BER),
    ENUM(WTAP_ENCAP_BLUETOOTH_BREDR_BB),
    ENUM(WTAP_ENCAP_BLUETOOTH_H4),
    ENUM(WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR),
    ENUM(WTAP_ENCAP_BLUETOOTH_HCI),
    ENUM(WTAP_ENCAP_BLUETOOTH_LE_LL),
    ENUM(WTAP_ENCAP_BLUETOOTH_LE_LL_WITH_PHDR),
    ENUM(WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR),
    ENUM(WTAP_ENCAP_CAN20B),
    ENUM(WTAP_ENCAP_CATAPULT_DCT2000),
    ENUM(WTAP_ENCAP_CHDLC),
    ENUM(WTAP_ENCAP_CHDLC_WITH_PHDR),
    ENUM(WTAP_ENCAP_CISCO_IOS),
    ENUM(WTAP_ENCAP_COSINE),
    ENUM(WTAP_ENCAP_DBUS),
    ENUM(WTAP_ENCAP_DOCSIS),
    ENUM(WTAP_ENCAP_DOCSIS31_XRA31),
    ENUM(WTAP_ENCAP_DPAUXMON),
    ENUM(WTAP_ENCAP_DPNSS),
    ENUM(WTAP_ENCAP_DVBCI),
    ENUM(WTAP_ENCAP_EBHSCR),
    ENUM(WTAP_ENCAP_ENC),
    ENUM(WTAP_ENCAP_EPON),
    ENUM(WTAP_ENCAP_ERF),
    ENUM(WTAP_ENCAP_ERI_ENB_LOG),
    ENUM(WTAP_ENCAP_ETHERNET),
    ENUM(WTAP_ENCAP_ETHERNET_MPACKET),
    ENUM(WTAP_ENCAP_ETW),
    ENUM(WTAP_ENCAP_FDDI),
    ENUM(WTAP_ENCAP_FDDI_BITSWAPPED),
    ENUM(WTAP_ENCAP_FIBRE_CHANNEL_FC2),
    ENUM(WTAP_ENCAP_FIBRE_CHANNEL_FC2_WITH_FRAME_DELIMS),
    ENUM(WTAP_ENCAP_FIRA_UCI),
    ENUM(WTAP_ENCAP_FLEXRAY),
    ENUM(WTAP_ENCAP_FRELAY),
    ENUM(WTAP_ENCAP_FRELAY_WITH_PHDR),
    ENUM(WTAP_ENCAP_GCOM_SERIAL),
    ENUM(WTAP_ENCAP_GCOM_TIE1),
    ENUM(WTAP_ENCAP_GFP_F),
    ENUM(WTAP_ENCAP_GFP_T),
    ENUM(WTAP_ENCAP_GPRS_LLC),
    ENUM(WTAP_ENCAP_GSM_UM),
    ENUM(WTAP_ENCAP_HHDLC),
    ENUM(WTAP_ENCAP_I2C_LINUX),
    ENUM(WTAP_ENCAP_IEEE802_15_4),
    ENUM(WTAP_ENCAP_IEEE802_15_4_NOFCS),
    ENUM(WTAP_ENCAP_IEEE802_15_4_NONASK_PHY),
    ENUM(WTAP_ENCAP_IEEE802_15_4_TAP),
    ENUM(WTAP_ENCAP_IEEE802_16_MAC_CPS),
    ENUM(WTAP_ENCAP_IEEE_802_11),
    ENUM(WTAP_ENCAP_IEEE_802_11_AVS),
    ENUM(WTAP_ENCAP_IEEE_802_11_NETMON),
    ENUM(WTAP_ENCAP_IEEE_802_11_PRISM),
    ENUM(WTAP_ENCAP_IEEE_802_11_RADIOTAP),
    ENUM(WTAP_ENCAP_IEEE_802_11_WITH_RADIO),
    ENUM(WTAP_ENCAP_INFINIBAND),
    ENUM(WTAP_ENCAP_IPMB_KONTRON),
    ENUM(WTAP_ENCAP_IPMI_TRACE),
    ENUM(WTAP_ENCAP_IPNET),
    ENUM(WTAP_ENCAP_IP_OVER_FC),
    ENUM(WTAP_ENCAP_IP_OVER_IB_PCAP),
    ENUM(WTAP_ENCAP_IP_OVER_IB_SNOOP),
    ENUM(WTAP_ENCAP_IRDA),
    ENUM(WTAP_ENCAP_ISDN),
    ENUM(WTAP_ENCAP_ISO14443),
    ENUM(WTAP_ENCAP_IXVERIWAVE),
    ENUM(WTAP_ENCAP_JPEG_JFIF),
    ENUM(WTAP_ENCAP_JSON),
    ENUM(WTAP_ENCAP_JUNIPER_ATM1),
    ENUM(WTAP_ENCAP_JUNIPER_ATM2),
    ENUM(WTAP_ENCAP_JUNIPER_CHDLC),
    ENUM(WTAP_ENCAP_JUNIPER_ETHER),
    ENUM(WTAP_ENCAP_JUNIPER_FRELAY),
    ENUM(WTAP_ENCAP_JUNIPER_GGSN),
    ENUM(WTAP_ENCAP_JUNIPER_MLFR),
    ENUM(WTAP_ENCAP_JUNIPER_MLPPP),
    ENUM(WTAP_ENCAP_JUNIPER_PPP),
    ENUM(WTAP_ENCAP_JUNIPER_PPPOE),
    ENUM(WTAP_ENCAP_JUNIPER_ST),
    ENUM(WTAP_ENCAP_JUNIPER_SVCS),
    ENUM(WTAP_ENCAP_JUNIPER_VN),
    ENUM(WTAP_ENCAP_JUNIPER_VP),
    ENUM(WTAP_ENCAP_K12),
    ENUM(WTAP_ENCAP_LAPB),
    ENUM(WTAP_ENCAP_LAPD),
    ENUM(WTAP_ENCAP_LAYER1_EVENT),
    ENUM(WTAP_ENCAP_LIN),
    ENUM(WTAP_ENCAP_LINUX_ATM_CLIP),
    ENUM(WTAP_ENCAP_LINUX_LAPD),
    ENUM(WTAP_ENCAP_LOCALTALK),
    ENUM(WTAP_ENCAP_LOGCAT),
    ENUM(WTAP_ENCAP_LOGCAT_BRIEF),
    ENUM(WTAP_ENCAP_LOGCAT_LONG),
    ENUM(WTAP_ENCAP_LOGCAT_PROCESS),
    ENUM(WTAP_ENCAP_LOGCAT_TAG),
    ENUM(WTAP_ENCAP_LOGCAT_THREAD),
    ENUM(WTAP_ENCAP_LOGCAT_THREADTIME),
    ENUM(WTAP_ENCAP_LOGCAT_TIME),
    ENUM(WTAP_ENCAP_LOG_3GPP),
    ENUM(WTAP_ENCAP_LOOP),
    ENUM(WTAP_ENCAP_LORATAP),
    ENUM(WTAP_ENCAP_MA_WFP_CAPTURE_2V4),
    ENUM(WTAP_ENCAP_MA_WFP_CAPTURE_2V6),
    ENUM(WTAP_ENCAP_MA_WFP_CAPTURE_AUTH_V4),
    ENUM(WTAP_ENCAP_MA_WFP_CAPTURE_AUTH_V6),
    ENUM(WTAP_ENCAP_MA_WFP_CAPTURE_V4),
    ENUM(WTAP_ENCAP_MA_WFP_CAPTURE_V6),
    ENUM(WTAP_ENCAP_MIME),
    ENUM(WTAP_ENCAP_MOST),
    ENUM(WTAP_ENCAP_MP4),
    ENUM(WTAP_ENCAP_MPEG),
    ENUM(WTAP_ENCAP_MPEG_2_TS),
    ENUM(WTAP_ENCAP_MTP2),
    ENUM(WTAP_ENCAP_MTP2_WITH_PHDR),
    ENUM(WTAP_ENCAP_MTP3),
    ENUM(WTAP_ENCAP_MUX27010),
    ENUM(WTAP_ENCAP_NETANALYZER),
    ENUM(WTAP_ENCAP_NETANALYZER_TRANSPARENT),
    ENUM(WTAP_ENCAP_NETLINK),
    ENUM(WTAP_ENCAP_NETMON_HEADER),
    ENUM(WTAP_ENCAP_NETMON_NETWORK_INFO_EX),
    ENUM(WTAP_ENCAP_NETMON_NET_FILTER),
    ENUM(WTAP_ENCAP_NETMON_NET_NETEVENT),
    ENUM(WTAP_ENCAP_NETTL_ETHERNET),
    ENUM(WTAP_ENCAP_NETTL_FDDI),
    ENUM(WTAP_ENCAP_NETTL_RAW_ICMP),
    ENUM(WTAP_ENCAP_NETTL_RAW_ICMPV6),
    ENUM(WTAP_ENCAP_NETTL_RAW_IP),
    ENUM(WTAP_ENCAP_NETTL_RAW_TELNET),
    ENUM(WTAP_ENCAP_NETTL_TOKEN_RING),
    ENUM(WTAP_ENCAP_NETTL_UNKNOWN),
    ENUM(WTAP_ENCAP_NETTL_X25),
    ENUM(WTAP_ENCAP_NFC_LLCP),
    ENUM(WTAP_ENCAP_NFLOG),
    ENUM(WTAP_ENCAP_NONE),
    ENUM(WTAP_ENCAP_NORDIC_BLE),
    ENUM(WTAP_ENCAP_NSTRACE_1_0),
    ENUM(WTAP_ENCAP_NSTRACE_2_0),
    ENUM(WTAP_ENCAP_NSTRACE_3_0),
    ENUM(WTAP_ENCAP_NSTRACE_3_5),
    ENUM(WTAP_ENCAP_NULL),
    ENUM(WTAP_ENCAP_OLD_PFLOG),
    ENUM(WTAP_ENCAP_PACKETLOGGER),
    ENUM(WTAP_ENCAP_PER_PACKET),
    ENUM(WTAP_ENCAP_PFLOG),
    ENUM(WTAP_ENCAP_PKTAP),
    ENUM(WTAP_ENCAP_PPI),
    ENUM(WTAP_ENCAP_PPP),
    ENUM(WTAP_ENCAP_PPP_ETHER),
    ENUM(WTAP_ENCAP_PPP_WITH_PHDR),
    ENUM(WTAP_ENCAP_RAW_IP),
    ENUM(WTAP_ENCAP_RAW_IP4),
    ENUM(WTAP_ENCAP_RAW_IP6),
    ENUM(WTAP_ENCAP_RAW_IPFIX),
    ENUM(WTAP_ENCAP_REDBACK),
    ENUM(WTAP_ENCAP_RFC7468),
    ENUM(WTAP_ENCAP_RTAC_SERIAL),
    ENUM(WTAP_ENCAP_RUBY_MARSHAL),
    ENUM(WTAP_ENCAP_SCCP),
    ENUM(WTAP_ENCAP_SCTP),
    ENUM(WTAP_ENCAP_SDH),
    ENUM(WTAP_ENCAP_SDLC),
    ENUM(WTAP_ENCAP_SILABS_DEBUG_CHANNEL),
    ENUM(WTAP_ENCAP_SITA),
    ENUM(WTAP_ENCAP_SLIP),
    ENUM(WTAP_ENCAP_SLL),
    ENUM(WTAP_ENCAP_SLL2),
    ENUM(WTAP_ENCAP_SOCKETCAN),
    ENUM(WTAP_ENCAP_STANAG_4607),
    ENUM(WTAP_ENCAP_STANAG_5066_D_PDU),
    ENUM(WTAP_ENCAP_SYMANTEC),
    ENUM(WTAP_ENCAP_SYSTEMD_JOURNAL),
    ENUM(WTAP_ENCAP_TNEF),
    ENUM(WTAP_ENCAP_TOKEN_RING),
    ENUM(WTAP_ENCAP_TZSP),
    ENUM(WTAP_ENCAP_UNKNOWN),
    ENUM(WTAP_ENCAP_USBPCAP),
    ENUM(WTAP_ENCAP_USB_2_0),
    ENUM(WTAP_ENCAP_USB_2_0_FULL_SPEED),
    ENUM(WTAP_ENCAP_USB_2_0_HIGH_SPEED),
    ENUM(WTAP_ENCAP_USB_2_0_LOW_SPEED),
    ENUM(WTAP_ENCAP_USB_DARWIN),
    ENUM(WTAP_ENCAP_USB_FREEBSD),
    ENUM(WTAP_ENCAP_USB_LINUX),
    ENUM(WTAP_ENCAP_USB_LINUX_MMAPPED),
    ENUM(WTAP_ENCAP_USER0),
    ENUM(WTAP_ENCAP_USER1),
    ENUM(WTAP_ENCAP_USER10),
    ENUM(WTAP_ENCAP_USER11),
    ENUM(WTAP_ENCAP_USER12),
    ENUM(WTAP_ENCAP_USER13),
    ENUM(WTAP_ENCAP_USER14),
    ENUM(WTAP_ENCAP_USER15),
    ENUM(WTAP_ENCAP_USER2),
    ENUM(WTAP_ENCAP_USER3),
    ENUM(WTAP_ENCAP_USER4),
    ENUM(WTAP_ENCAP_USER5),
    ENUM(WTAP_ENCAP_USER6),
    ENUM(WTAP_ENCAP_USER7),
    ENUM(WTAP_ENCAP_USER8),
    ENUM(WTAP_ENCAP_USER9),
    ENUM(WTAP_ENCAP_V5_EF),
    ENUM(WTAP_ENCAP_VPP),
    ENUM(WTAP_ENCAP_VSOCK),
    ENUM(WTAP_ENCAP_WFLEET_HDLC),
    ENUM(WTAP_ENCAP_WIRESHARK_UPPER_PDU),
    ENUM(WTAP_ENCAP_X2E_SERIAL),
    ENUM(WTAP_ENCAP_X2E_XORAYA),
    ENUM(WTAP_ENCAP_ZBNCP),
    ENUM(WTAP_ENCAP_ZWAVE_SERIAL),
    ENUM(WTAP_ERR_BAD_FILE),
    ENUM(WTAP_ERR_CANT_CLOSE),
    ENUM(WTAP_ERR_CANT_OPEN),
    ENUM(WTAP_ERR_CANT_SEEK),
    ENUM(WTAP_ERR_CANT_SEEK_COMPRESSED),
    ENUM(WTAP_ERR_CANT_WRITE),
    ENUM(WTAP_ERR_CANT_WRITE_TO_PIPE),
    ENUM(WTAP_ERR_CHECK_WSLUA),
    ENUM(WTAP_ERR_COMPRESSION_NOT_SUPPORTED),
    ENUM(WTAP_ERR_DECOMPRESS),
    ENUM(WTAP_ERR_DECOMPRESSION_NOT_SUPPORTED),
    ENUM(WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED),
    ENUM(WTAP_ERR_FILE_UNKNOWN_FORMAT),
    ENUM(WTAP_ERR_INTERNAL),
    ENUM(WTAP_ERR_NOT_REGULAR_FILE),
    ENUM(WTAP_ERR_PACKET_TOO_LARGE),
    ENUM(WTAP_ERR_RANDOM_OPEN_PIPE),
    ENUM(WTAP_ERR_RANDOM_OPEN_STDIN),
    ENUM(WTAP_ERR_SHORT_READ),
    ENUM(WTAP_ERR_SHORT_WRITE),
    ENUM(WTAP_ERR_TIME_STAMP_NOT_SUPPORTED),
    ENUM(WTAP_ERR_UNC_OVERFLOW),
    ENUM(WTAP_ERR_UNSUPPORTED),
    ENUM(WTAP_ERR_UNWRITABLE_ENCAP),
    ENUM(WTAP_ERR_UNWRITABLE_FILE_TYPE),
    ENUM(WTAP_ERR_UNWRITABLE_REC_DATA),
    ENUM(WTAP_ERR_UNWRITABLE_REC_TYPE),
    ENUM(WTAP_FILE_TYPE_SUBTYPE_UNKNOWN),
    ENUM(WTAP_GZIP_COMPRESSED),
    ENUM(WTAP_HAS_CAP_LEN),
    ENUM(WTAP_HAS_INTERFACE_ID),
    ENUM(WTAP_HAS_SECTION_NUMBER),
    ENUM(WTAP_HAS_TS),
    ENUM(WTAP_LZ4_COMPRESSED),
    ENUM(WTAP_MAX_PACKET_SIZE_DBUS),
    ENUM(WTAP_MAX_PACKET_SIZE_EBHSCR),
    ENUM(WTAP_MAX_PACKET_SIZE_STANDARD),
    ENUM(WTAP_MAX_PACKET_SIZE_USBPCAP),
    ENUM(WTAP_OPEN_ERROR),
    ENUM(WTAP_OPEN_MINE),
    ENUM(WTAP_OPEN_NOT_MINE),
    ENUM(WTAP_TSPREC_CSEC),
    ENUM(WTAP_TSPREC_DSEC),
    ENUM(WTAP_TSPREC_MSEC),
    ENUM(WTAP_TSPREC_NSEC),
    ENUM(WTAP_TSPREC_PER_PACKET),
    ENUM(WTAP_TSPREC_SEC),
    ENUM(WTAP_TSPREC_UNKNOWN),
    ENUM(WTAP_TSPREC_USEC),
    ENUM(WTAP_TYPE_AUTO),
    ENUM(WTAP_UNCOMPRESSED),
    ENUM(WTAP_ZSTD_COMPRESSED),
    { NULL, 0 },
};
