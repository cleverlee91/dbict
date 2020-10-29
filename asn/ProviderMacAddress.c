/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IEEE-1609-3-WEE"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#include "ProviderMacAddress.h"

int
ProviderMacAddress_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const MACaddress_t *st = (const MACaddress_t *)sptr;
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	size = st->size;
	
	if((size == 6)) {
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
 * This type is implemented using MACaddress,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_ProviderMacAddress_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	6	/* (SIZE(6..6)) */};
static const ber_tlv_tag_t asn_DEF_ProviderMacAddress_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (4 << 2))
};
asn_TYPE_descriptor_t asn_DEF_ProviderMacAddress = {
	"ProviderMacAddress",
	"ProviderMacAddress",
	&asn_OP_OCTET_STRING,
	asn_DEF_ProviderMacAddress_tags_1,
	sizeof(asn_DEF_ProviderMacAddress_tags_1)
		/sizeof(asn_DEF_ProviderMacAddress_tags_1[0]), /* 1 */
	asn_DEF_ProviderMacAddress_tags_1,	/* Same as above */
	sizeof(asn_DEF_ProviderMacAddress_tags_1)
		/sizeof(asn_DEF_ProviderMacAddress_tags_1[0]), /* 1 */
	{ &asn_OER_type_ProviderMacAddress_constr_1, 0, ProviderMacAddress_constraint },
	0, 0,	/* No members */
	&asn_SPC_OCTET_STRING_specs	/* Additional specs */
};

