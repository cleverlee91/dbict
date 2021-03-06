/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-CommonTypes"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#ifndef	_PduType_H_
#define	_PduType_H_


#include <asn_application.h>

/* Including external dependencies */
#include <ENUMERATED.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PduType {
	PduType_reserved	= 0,
	PduType_d80211frame	= 1,
	PduType_d16093frame	= 2,
	PduType_d16092data	= 3,
	PduType_d16093payload	= 4,
	PduType_dIpv6payload	= 5
} e_PduType;

/* PduType */
typedef ENUMERATED_t	 PduType_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PduType;
extern const asn_INTEGER_specifics_t asn_SPC_PduType_specs_1;
asn_struct_free_f PduType_free;
asn_struct_print_f PduType_print;
asn_constr_check_f PduType_constraint;
ber_type_decoder_f PduType_decode_ber;
der_type_encoder_f PduType_encode_der;
xer_type_decoder_f PduType_decode_xer;
xer_type_encoder_f PduType_encode_xer;
oer_type_decoder_f PduType_decode_oer;
oer_type_encoder_f PduType_encode_oer;

#ifdef __cplusplus
}
#endif

#endif	/* _PduType_H_ */
#include <asn_internal.h>
