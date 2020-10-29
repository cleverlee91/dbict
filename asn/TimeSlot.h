/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-CommonTypes"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#ifndef	_TimeSlot_H_
#define	_TimeSlot_H_


#include <asn_application.h>

/* Including external dependencies */
#include <ENUMERATED.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TimeSlot {
	TimeSlot_reserved	= 0,
	TimeSlot_alt_slot0	= 1,
	TimeSlot_alt_slot1	= 2,
	TimeSlot_continuous	= 3
} e_TimeSlot;

/* TimeSlot */
typedef ENUMERATED_t	 TimeSlot_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TimeSlot;
extern const asn_INTEGER_specifics_t asn_SPC_TimeSlot_specs_1;
asn_struct_free_f TimeSlot_free;
asn_struct_print_f TimeSlot_print;
asn_constr_check_f TimeSlot_constraint;
ber_type_decoder_f TimeSlot_decode_ber;
der_type_encoder_f TimeSlot_encode_der;
xer_type_decoder_f TimeSlot_decode_xer;
xer_type_encoder_f TimeSlot_encode_xer;
oer_type_decoder_f TimeSlot_decode_oer;
oer_type_encoder_f TimeSlot_encode_oer;

#ifdef __cplusplus
}
#endif

#endif	/* _TimeSlot_H_ */
#include <asn_internal.h>