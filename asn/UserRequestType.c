/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-wsm"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#include "UserRequestType.h"

int
UserRequestType_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 1)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

/*
 * This type is implemented using NativeInteger,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_UserRequestType_constr_1 CC_NOTUSED = {
	{ 1, 1 }	/* (0..1) */,
	-1};
static const ber_tlv_tag_t asn_DEF_UserRequestType_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (2 << 2))
};
asn_TYPE_descriptor_t asn_DEF_UserRequestType = {
	"UserRequestType",
	"UserRequestType",
	&asn_OP_NativeInteger,
	asn_DEF_UserRequestType_tags_1,
	sizeof(asn_DEF_UserRequestType_tags_1)
		/sizeof(asn_DEF_UserRequestType_tags_1[0]), /* 1 */
	asn_DEF_UserRequestType_tags_1,	/* Same as above */
	sizeof(asn_DEF_UserRequestType_tags_1)
		/sizeof(asn_DEF_UserRequestType_tags_1[0]), /* 1 */
	{ &asn_OER_type_UserRequestType_constr_1, 0, UserRequestType_constraint },
	0, 0,	/* Defined elsewhere */
	0	/* No specifics */
};

