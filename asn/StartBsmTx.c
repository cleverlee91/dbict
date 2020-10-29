/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-29451"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#include "StartBsmTx.h"

int
StartBsmTx_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
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
 * This type is implemented using StartWsmTx,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_StartBsmTx_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static const ber_tlv_tag_t asn_DEF_StartBsmTx_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_TYPE_descriptor_t asn_DEF_StartBsmTx = {
	"StartBsmTx",
	"StartBsmTx",
	&asn_OP_SEQUENCE,
	asn_DEF_StartBsmTx_tags_1,
	sizeof(asn_DEF_StartBsmTx_tags_1)
		/sizeof(asn_DEF_StartBsmTx_tags_1[0]), /* 1 */
	asn_DEF_StartBsmTx_tags_1,	/* Same as above */
	sizeof(asn_DEF_StartBsmTx_tags_1)
		/sizeof(asn_DEF_StartBsmTx_tags_1[0]), /* 1 */
	{ &asn_OER_type_StartBsmTx_constr_1, 0, StartBsmTx_constraint },
	asn_MBR_StartWsmTx_1,
	4,	/* Elements count */
	&asn_SPC_StartWsmTx_specs_1	/* Additional specs */
};

