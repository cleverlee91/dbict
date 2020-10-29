/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-80211"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#include "Dot11SetWsmTxInfo.h"

int
Dot11SetWsmTxInfo_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	
	if(1 /* No applicable constraints whatsoever */) {
		/* Nothing is here. See below */
	}
	
	return td->encoding_constraints.general_constraints(td, sptr, ctfailcb, app_key);
}

/*
 * This type is implemented using SetWsmTxInfo,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_Dot11SetWsmTxInfo_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static const ber_tlv_tag_t asn_DEF_Dot11SetWsmTxInfo_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_TYPE_descriptor_t asn_DEF_Dot11SetWsmTxInfo = {
	"Dot11SetWsmTxInfo",
	"Dot11SetWsmTxInfo",
	&asn_OP_SEQUENCE,
	asn_DEF_Dot11SetWsmTxInfo_tags_1,
	sizeof(asn_DEF_Dot11SetWsmTxInfo_tags_1)
		/sizeof(asn_DEF_Dot11SetWsmTxInfo_tags_1[0]), /* 1 */
	asn_DEF_Dot11SetWsmTxInfo_tags_1,	/* Same as above */
	sizeof(asn_DEF_Dot11SetWsmTxInfo_tags_1)
		/sizeof(asn_DEF_Dot11SetWsmTxInfo_tags_1[0]), /* 1 */
	{ &asn_OER_type_Dot11SetWsmTxInfo_constr_1, 0, Dot11SetWsmTxInfo_constraint },
	asn_MBR_SetWsmTxInfo_1,
	14,	/* Elements count */
	&asn_SPC_SetWsmTxInfo_specs_1	/* Additional specs */
};

