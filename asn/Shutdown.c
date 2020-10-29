/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-SutControl"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#include "Shutdown.h"

int
Shutdown_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	BOOLEAN_t value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = (*(const long *)sptr) ? 1 : 0;
	
	if((value >= 1)) {
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
 * This type is implemented using BOOLEAN,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_Shutdown_constr_1 CC_NOTUSED = {
	{ 1, 1 }	/* (1..1) */,
	-1};
static const ber_tlv_tag_t asn_DEF_Shutdown_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (1 << 2))
};
asn_TYPE_descriptor_t asn_DEF_Shutdown = {
	"Shutdown",
	"Shutdown",
	&asn_OP_BOOLEAN,
	asn_DEF_Shutdown_tags_1,
	sizeof(asn_DEF_Shutdown_tags_1)
		/sizeof(asn_DEF_Shutdown_tags_1[0]), /* 1 */
	asn_DEF_Shutdown_tags_1,	/* Same as above */
	sizeof(asn_DEF_Shutdown_tags_1)
		/sizeof(asn_DEF_Shutdown_tags_1[0]), /* 1 */
	{ &asn_OER_type_Shutdown_constr_1, 0, Shutdown_constraint },
	0, 0,	/* No members */
	0	/* No specifics */
};

