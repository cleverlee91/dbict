/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-SutControl"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#ifndef	_SetGpsTime_H_
#define	_SetGpsTime_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Time64.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SetGpsTime */
typedef Time64_t	 SetGpsTime_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SetGpsTime;
asn_struct_free_f SetGpsTime_free;
asn_struct_print_f SetGpsTime_print;
asn_constr_check_f SetGpsTime_constraint;
ber_type_decoder_f SetGpsTime_decode_ber;
der_type_encoder_f SetGpsTime_encode_der;
xer_type_decoder_f SetGpsTime_decode_xer;
xer_type_encoder_f SetGpsTime_encode_xer;
oer_type_decoder_f SetGpsTime_decode_oer;
oer_type_encoder_f SetGpsTime_encode_oer;

#ifdef __cplusplus
}
#endif

#endif	/* _SetGpsTime_H_ */
#include <asn_internal.h>
