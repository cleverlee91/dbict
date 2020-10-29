/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IEEE-1609-3-WSM"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#ifndef	_NoSubtypeProcessing_H_
#define	_NoSubtypeProcessing_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>
#include "ShortMsgVersion.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NoSubtypeProcessing */
typedef struct NoSubtypeProcessing {
	BIT_STRING_t	 optBit;
	ShortMsgVersion_t	 version;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NoSubtypeProcessing_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NoSubtypeProcessing;
extern asn_SEQUENCE_specifics_t asn_SPC_NoSubtypeProcessing_specs_1;
extern asn_TYPE_member_t asn_MBR_NoSubtypeProcessing_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _NoSubtypeProcessing_H_ */
#include <asn_internal.h>
