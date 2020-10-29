/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-wsm"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#ifndef	_UserRequestType_H_
#define	_UserRequestType_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UserRequestType {
	UserRequestType_autoAccessOnMatch	= 0,
	UserRequestType_noSchAccess	= 1
} e_UserRequestType;

/* UserRequestType */
typedef long	 UserRequestType_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UserRequestType;
asn_struct_free_f UserRequestType_free;
asn_struct_print_f UserRequestType_print;
asn_constr_check_f UserRequestType_constraint;
ber_type_decoder_f UserRequestType_decode_ber;
der_type_encoder_f UserRequestType_encode_der;
xer_type_decoder_f UserRequestType_decode_xer;
xer_type_encoder_f UserRequestType_encode_xer;
oer_type_decoder_f UserRequestType_decode_oer;
oer_type_encoder_f UserRequestType_encode_oer;

#ifdef __cplusplus
}
#endif

#endif	/* _UserRequestType_H_ */
#include <asn_internal.h>