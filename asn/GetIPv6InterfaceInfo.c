/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-ip"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#include "GetIPv6InterfaceInfo.h"

static int
memb_radio_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
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

static asn_oer_constraints_t asn_OER_memb_radio_constr_2 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_TYPE_member_t asn_MBR_GetIPv6InterfaceInfo_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct GetIPv6InterfaceInfo, radio),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RadioInterface,
		0,
		{ &asn_OER_memb_radio_constr_2, 0,  memb_radio_constraint_1 },
		0, 0, /* No default value */
		"radio"
		},
};
static const ber_tlv_tag_t asn_DEF_GetIPv6InterfaceInfo_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_GetIPv6InterfaceInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* radio */
};
asn_SEQUENCE_specifics_t asn_SPC_GetIPv6InterfaceInfo_specs_1 = {
	sizeof(struct GetIPv6InterfaceInfo),
	offsetof(struct GetIPv6InterfaceInfo, _asn_ctx),
	asn_MAP_GetIPv6InterfaceInfo_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_GetIPv6InterfaceInfo = {
	"GetIPv6InterfaceInfo",
	"GetIPv6InterfaceInfo",
	&asn_OP_SEQUENCE,
	asn_DEF_GetIPv6InterfaceInfo_tags_1,
	sizeof(asn_DEF_GetIPv6InterfaceInfo_tags_1)
		/sizeof(asn_DEF_GetIPv6InterfaceInfo_tags_1[0]), /* 1 */
	asn_DEF_GetIPv6InterfaceInfo_tags_1,	/* Same as above */
	sizeof(asn_DEF_GetIPv6InterfaceInfo_tags_1)
		/sizeof(asn_DEF_GetIPv6InterfaceInfo_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_GetIPv6InterfaceInfo_1,
	1,	/* Elements count */
	&asn_SPC_GetIPv6InterfaceInfo_specs_1	/* Additional specs */
};

