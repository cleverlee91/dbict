/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-SutControl"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#ifndef	_Restart_H_
#define	_Restart_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BOOLEAN.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Restart */
typedef BOOLEAN_t	 Restart_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Restart;
asn_struct_free_f Restart_free;
asn_struct_print_f Restart_print;
asn_constr_check_f Restart_constraint;
ber_type_decoder_f Restart_decode_ber;
der_type_encoder_f Restart_encode_der;
xer_type_decoder_f Restart_decode_xer;
xer_type_encoder_f Restart_encode_xer;
oer_type_decoder_f Restart_decode_oer;
oer_type_encoder_f Restart_encode_oer;

#ifdef __cplusplus
}
#endif

#endif	/* _Restart_H_ */
#include <asn_internal.h>
