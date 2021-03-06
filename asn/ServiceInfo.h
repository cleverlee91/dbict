/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IEEE-1609-3-WSA"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#ifndef	_ServiceInfo_H_
#define	_ServiceInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include "VarLengthNumber.h"
#include "ChannelIndex.h"
#include "ChannelOptions.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ServiceInfo */
typedef struct ServiceInfo {
	VarLengthNumber_t	 serviceID;
	ChannelIndex_t	 channelIndex;
	ChannelOptions_t	 chOptions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ServiceInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ServiceInfo;
extern asn_SEQUENCE_specifics_t asn_SPC_ServiceInfo_specs_1;
extern asn_TYPE_member_t asn_MBR_ServiceInfo_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _ServiceInfo_H_ */
#include <asn_internal.h>
