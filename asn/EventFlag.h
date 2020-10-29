/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-eventHandling"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#ifndef	_EventFlag_H_
#define	_EventFlag_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum EventFlag {
	EventFlag_e80211PktRx	= 0,
	EventFlag_e16093PktRx	= 1,
	EventFlag_eWSM	= 2,
	EventFlag_eIpv6PktRx	= 3,
	EventFlag_eIcmp6PktRx	= 4,
	EventFlag_ePsidServiceActive	= 5,
	EventFlag_eWSAServiceActive	= 6,
	EventFlag_eIpv6ConfigChanged	= 7,
	EventFlag_verificationCompleteWithResult	= 8
} e_EventFlag;

/* EventFlag */
typedef BIT_STRING_t	 EventFlag_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_EventFlag;
asn_struct_free_f EventFlag_free;
asn_struct_print_f EventFlag_print;
asn_constr_check_f EventFlag_constraint;
ber_type_decoder_f EventFlag_decode_ber;
der_type_encoder_f EventFlag_encode_der;
xer_type_decoder_f EventFlag_decode_xer;
xer_type_encoder_f EventFlag_encode_xer;
oer_type_decoder_f EventFlag_decode_oer;
oer_type_encoder_f EventFlag_encode_oer;

#ifdef __cplusplus
}
#endif

#endif	/* _EventFlag_H_ */
#include <asn_internal.h>