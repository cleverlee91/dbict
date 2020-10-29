/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-SutControl"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#include "SetGpsTime.h"

int
SetGpsTime_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const Time64_t *st = (const Time64_t *)sptr;
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	if(asn_INTEGER2long(st, &value)) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value too large (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	if((value >= 0 && value <= 9223372036854775807)) {
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
 * This type is implemented using Time64,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_SetGpsTime_constr_1 CC_NOTUSED = {
	{ 8, 1 }	/* (0..9223372036854775807) */,
	-1};
static const ber_tlv_tag_t asn_DEF_SetGpsTime_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (2 << 2))
};
asn_TYPE_descriptor_t asn_DEF_SetGpsTime = {
	"SetGpsTime",
	"SetGpsTime",
	&asn_OP_INTEGER,
	asn_DEF_SetGpsTime_tags_1,
	sizeof(asn_DEF_SetGpsTime_tags_1)
		/sizeof(asn_DEF_SetGpsTime_tags_1[0]), /* 1 */
	asn_DEF_SetGpsTime_tags_1,	/* Same as above */
	sizeof(asn_DEF_SetGpsTime_tags_1)
		/sizeof(asn_DEF_SetGpsTime_tags_1[0]), /* 1 */
	{ &asn_OER_type_SetGpsTime_constr_1, 0, SetGpsTime_constraint },
	0, 0,	/* No members */
	0	/* No specifics */
};

