/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-ip"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#ifndef	_StopIPv6Ping_H_
#define	_StopIPv6Ping_H_


#include <asn_application.h>

/* Including external dependencies */
#include "IPv6TxRecord.h"

#ifdef __cplusplus
extern "C" {
#endif

/* StopIPv6Ping */
typedef IPv6TxRecord_t	 StopIPv6Ping_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_StopIPv6Ping;
asn_struct_free_f StopIPv6Ping_free;
asn_struct_print_f StopIPv6Ping_print;
asn_constr_check_f StopIPv6Ping_constraint;
ber_type_decoder_f StopIPv6Ping_decode_ber;
der_type_encoder_f StopIPv6Ping_encode_der;
xer_type_decoder_f StopIPv6Ping_decode_xer;
xer_type_encoder_f StopIPv6Ping_encode_xer;
oer_type_decoder_f StopIPv6Ping_decode_oer;
oer_type_encoder_f StopIPv6Ping_encode_oer;

#ifdef __cplusplus
}
#endif

#endif	/* _StopIPv6Ping_H_ */
#include <asn_internal.h>
