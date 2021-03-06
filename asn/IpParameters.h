/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-indication"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#ifndef	_IpParameters_H_
#define	_IpParameters_H_


#include <asn_application.h>

/* Including external dependencies */
#include <UTF8String.h>
#include "IPv6Address.h"
#include <ENUMERATED.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum IpParameters__protocol {
	IpParameters__protocol_tcp	= 0,
	IpParameters__protocol_udp	= 1,
	IpParameters__protocol_icmpv6	= 2
} e_IpParameters__protocol;

/* IpParameters */
typedef struct IpParameters {
	UTF8String_t	 interfaceName;
	IPv6Address_t	 sourceIPaddress;
	ENUMERATED_t	 protocol;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} IpParameters_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_protocol_4;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_IpParameters;
extern asn_SEQUENCE_specifics_t asn_SPC_IpParameters_specs_1;
extern asn_TYPE_member_t asn_MBR_IpParameters_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _IpParameters_H_ */
#include <asn_internal.h>
