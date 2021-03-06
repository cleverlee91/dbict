/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-wsm"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#ifndef	_WsmServiceInfo_H_
#define	_WsmServiceInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Psid.h"
#include "ChannelNumber80211.h"
#include "WsmChannelOptions.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* WsmServiceInfo */
typedef struct WsmServiceInfo {
	Psid_t	 serviceID;
	ChannelNumber80211_t	 channelNumber;
	WsmChannelOptions_t	 chOptions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} WsmServiceInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_WsmServiceInfo;
extern asn_SEQUENCE_specifics_t asn_SPC_WsmServiceInfo_specs_1;
extern asn_TYPE_member_t asn_MBR_WsmServiceInfo_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _WsmServiceInfo_H_ */
#include <asn_internal.h>
