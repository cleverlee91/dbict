/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-wsm"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#include "StopWsaTxPeriodic.h"

asn_TYPE_member_t asn_MBR_StopWsaTxPeriodic_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct StopWsaTxPeriodic, radio),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RadioInterface,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"radio"
		},
};
static const ber_tlv_tag_t asn_DEF_StopWsaTxPeriodic_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_StopWsaTxPeriodic_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* radio */
};
asn_SEQUENCE_specifics_t asn_SPC_StopWsaTxPeriodic_specs_1 = {
	sizeof(struct StopWsaTxPeriodic),
	offsetof(struct StopWsaTxPeriodic, _asn_ctx),
	asn_MAP_StopWsaTxPeriodic_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_StopWsaTxPeriodic = {
	"StopWsaTxPeriodic",
	"StopWsaTxPeriodic",
	&asn_OP_SEQUENCE,
	asn_DEF_StopWsaTxPeriodic_tags_1,
	sizeof(asn_DEF_StopWsaTxPeriodic_tags_1)
		/sizeof(asn_DEF_StopWsaTxPeriodic_tags_1[0]), /* 1 */
	asn_DEF_StopWsaTxPeriodic_tags_1,	/* Same as above */
	sizeof(asn_DEF_StopWsaTxPeriodic_tags_1)
		/sizeof(asn_DEF_StopWsaTxPeriodic_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_StopWsaTxPeriodic_1,
	1,	/* Elements count */
	&asn_SPC_StopWsaTxPeriodic_specs_1	/* Additional specs */
};

