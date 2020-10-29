/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-wsm"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#include "WsmServiceInfo.h"

asn_TYPE_member_t asn_MBR_WsmServiceInfo_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct WsmServiceInfo, serviceID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_Psid,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"serviceID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct WsmServiceInfo, channelNumber),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ChannelNumber80211,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"channelNumber"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct WsmServiceInfo, chOptions),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_WsmChannelOptions,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"chOptions"
		},
};
static const ber_tlv_tag_t asn_DEF_WsmServiceInfo_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_WsmServiceInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* serviceID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* channelNumber */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* chOptions */
};
asn_SEQUENCE_specifics_t asn_SPC_WsmServiceInfo_specs_1 = {
	sizeof(struct WsmServiceInfo),
	offsetof(struct WsmServiceInfo, _asn_ctx),
	asn_MAP_WsmServiceInfo_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_WsmServiceInfo = {
	"WsmServiceInfo",
	"WsmServiceInfo",
	&asn_OP_SEQUENCE,
	asn_DEF_WsmServiceInfo_tags_1,
	sizeof(asn_DEF_WsmServiceInfo_tags_1)
		/sizeof(asn_DEF_WsmServiceInfo_tags_1[0]), /* 1 */
	asn_DEF_WsmServiceInfo_tags_1,	/* Same as above */
	sizeof(asn_DEF_WsmServiceInfo_tags_1)
		/sizeof(asn_DEF_WsmServiceInfo_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_WsmServiceInfo_1,
	3,	/* Elements count */
	&asn_SPC_WsmServiceInfo_specs_1	/* Additional specs */
};

