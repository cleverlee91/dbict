/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-eventHandling"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#ifndef	_EventHandling_H_
#define	_EventHandling_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RxFlag.h"
#include "EventFlag.h"
#include "PduType.h"
#include "SecurityFlag.h"
#include "EventParamsChoice.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* EventHandling */
typedef struct EventHandling {
	RxFlag_t	*rxFlag	/* DEFAULT '000'BHime */;
	EventFlag_t	*eventFlag	/* DEFAULT '00'HHHime */;
	PduType_t	*forwardPdu	/* OPTIONAL */;
	SecurityFlag_t	*securityFlag	/* DEFAULT '0000'BHme */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	EventParamsChoice_t	*eventParamsChoice	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} EventHandling_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_EventHandling;
extern asn_SEQUENCE_specifics_t asn_SPC_EventHandling_specs_1;
extern asn_TYPE_member_t asn_MBR_EventHandling_1[5];

#ifdef __cplusplus
}
#endif

#endif	/* _EventHandling_H_ */
#include <asn_internal.h>
