/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-indication"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#ifndef	_ServiceParameters_H_
#define	_ServiceParameters_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Psid;

/* ServiceParameters */
typedef struct ServiceParameters {
	struct ServiceParameters__psid {
		A_SEQUENCE_OF(struct Psid) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} psid;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ServiceParameters_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ServiceParameters;
extern asn_SEQUENCE_specifics_t asn_SPC_ServiceParameters_specs_1;
extern asn_TYPE_member_t asn_MBR_ServiceParameters_1[1];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "Psid.h"

#endif	/* _ServiceParameters_H_ */
#include <asn_internal.h>
