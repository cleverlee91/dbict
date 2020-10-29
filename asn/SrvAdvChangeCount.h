/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IEEE-1609-3-WSA"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#ifndef	_SrvAdvChangeCount_H_
#define	_SrvAdvChangeCount_H_


#include <asn_application.h>

/* Including external dependencies */
#include "SrvAdvID.h"
#include "SrvAdvContentCount.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SrvAdvChangeCount */
typedef struct SrvAdvChangeCount {
	SrvAdvID_t	 saID;
	SrvAdvContentCount_t	 contentCount;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SrvAdvChangeCount_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SrvAdvChangeCount;
extern asn_SEQUENCE_specifics_t asn_SPC_SrvAdvChangeCount_specs_1;
extern asn_TYPE_member_t asn_MBR_SrvAdvChangeCount_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _SrvAdvChangeCount_H_ */
#include <asn_internal.h>
