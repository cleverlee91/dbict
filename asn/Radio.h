/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-CommonTypes"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#ifndef	_Radio_H_
#define	_Radio_H_


#include <asn_application.h>

/* Including external dependencies */
#include <ENUMERATED.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Radio {
	Radio_radio0	= 0,
	Radio_radio1	= 1,
	Radio_radio2	= 2,
	Radio_radio3	= 3
} e_Radio;

/* Radio */
typedef ENUMERATED_t	 Radio_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Radio;
extern const asn_INTEGER_specifics_t asn_SPC_Radio_specs_1;
asn_struct_free_f Radio_free;
asn_struct_print_f Radio_print;
asn_constr_check_f Radio_constraint;
ber_type_decoder_f Radio_decode_ber;
der_type_encoder_f Radio_encode_der;
xer_type_decoder_f Radio_decode_xer;
xer_type_encoder_f Radio_encode_xer;
oer_type_decoder_f Radio_decode_oer;
oer_type_encoder_f Radio_encode_oer;

#ifdef __cplusplus
}
#endif

#endif	/* _Radio_H_ */
#include <asn_internal.h>
