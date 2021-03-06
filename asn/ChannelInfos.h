/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IEEE-1609-3-WSA"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#ifndef	_ChannelInfos_H_
#define	_ChannelInfos_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ChannelInfo;

/* ChannelInfos */
typedef struct ChannelInfos {
	A_SEQUENCE_OF(struct ChannelInfo) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ChannelInfos_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ChannelInfos;
extern asn_SET_OF_specifics_t asn_SPC_ChannelInfos_specs_1;
extern asn_TYPE_member_t asn_MBR_ChannelInfos_1[1];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ChannelInfo.h"

#endif	/* _ChannelInfos_H_ */
#include <asn_internal.h>
