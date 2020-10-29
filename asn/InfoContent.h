/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-responseInfo"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#ifndef	_InfoContent_H_
#define	_InfoContent_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Ipv6InterfaceInfo.h"
#include "SutInfo.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum InfoContent_PR {
	InfoContent_PR_NOTHING,	/* No components present */
	InfoContent_PR_ipv6InterfaceInfo,
	InfoContent_PR_sutInfo
	/* Extensions may appear below */
	
} InfoContent_PR;

/* InfoContent */
typedef struct InfoContent {
	InfoContent_PR present;
	union InfoContent_u {
		Ipv6InterfaceInfo_t	 ipv6InterfaceInfo;
		SutInfo_t	 sutInfo;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InfoContent_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InfoContent;
extern asn_CHOICE_specifics_t asn_SPC_InfoContent_specs_1;
extern asn_TYPE_member_t asn_MBR_InfoContent_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _InfoContent_H_ */
#include <asn_internal.h>
