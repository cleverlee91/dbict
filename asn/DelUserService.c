/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-wsm"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#include "DelUserService.h"

asn_TYPE_member_t asn_MBR_DelUserService_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DelUserService, psid),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_Psid,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"psid"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DelUserService, radio),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RadioInterface,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"radio"
		},
};
static const ber_tlv_tag_t asn_DEF_DelUserService_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_DelUserService_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* psid */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* radio */
};
asn_SEQUENCE_specifics_t asn_SPC_DelUserService_specs_1 = {
	sizeof(struct DelUserService),
	offsetof(struct DelUserService, _asn_ctx),
	asn_MAP_DelUserService_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	2,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_DelUserService = {
	"DelUserService",
	"DelUserService",
	&asn_OP_SEQUENCE,
	asn_DEF_DelUserService_tags_1,
	sizeof(asn_DEF_DelUserService_tags_1)
		/sizeof(asn_DEF_DelUserService_tags_1[0]), /* 1 */
	asn_DEF_DelUserService_tags_1,	/* Same as above */
	sizeof(asn_DEF_DelUserService_tags_1)
		/sizeof(asn_DEF_DelUserService_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_DelUserService_1,
	2,	/* Elements count */
	&asn_SPC_DelUserService_specs_1	/* Additional specs */
};

