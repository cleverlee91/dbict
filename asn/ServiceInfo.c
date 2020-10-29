/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IEEE-1609-3-WSA"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#include "ServiceInfo.h"

asn_TYPE_member_t asn_MBR_ServiceInfo_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct ServiceInfo, serviceID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_VarLengthNumber,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"serviceID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct ServiceInfo, channelIndex),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ChannelIndex,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"channelIndex"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct ServiceInfo, chOptions),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ChannelOptions,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"chOptions"
		},
};
static const ber_tlv_tag_t asn_DEF_ServiceInfo_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_ServiceInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* serviceID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* channelIndex */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* chOptions */
};
asn_SEQUENCE_specifics_t asn_SPC_ServiceInfo_specs_1 = {
	sizeof(struct ServiceInfo),
	offsetof(struct ServiceInfo, _asn_ctx),
	asn_MAP_ServiceInfo_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_ServiceInfo = {
	"ServiceInfo",
	"ServiceInfo",
	&asn_OP_SEQUENCE,
	asn_DEF_ServiceInfo_tags_1,
	sizeof(asn_DEF_ServiceInfo_tags_1)
		/sizeof(asn_DEF_ServiceInfo_tags_1[0]), /* 1 */
	asn_DEF_ServiceInfo_tags_1,	/* Same as above */
	sizeof(asn_DEF_ServiceInfo_tags_1)
		/sizeof(asn_DEF_ServiceInfo_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_ServiceInfo_1,
	3,	/* Elements count */
	&asn_SPC_ServiceInfo_specs_1	/* Additional specs */
};
