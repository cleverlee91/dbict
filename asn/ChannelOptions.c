/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IEEE-1609-3-WSA"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#include "ChannelOptions.h"

asn_TYPE_member_t asn_MBR_ChannelOptions_1[] = {
	{ ATF_POINTER, 3, offsetof(struct ChannelOptions, mandApp),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MandApp,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mandApp"
		},
	{ ATF_POINTER, 2, offsetof(struct ChannelOptions, serviceProviderPort),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ReplyAddress,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"serviceProviderPort"
		},
	{ ATF_POINTER, 1, offsetof(struct ChannelOptions, extensions),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ServiceInfoExts,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"extensions"
		},
};
static const int asn_MAP_ChannelOptions_oms_1[] = { 0, 1, 2 };
static const ber_tlv_tag_t asn_DEF_ChannelOptions_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_ChannelOptions_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* mandApp */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* serviceProviderPort */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* extensions */
};
asn_SEQUENCE_specifics_t asn_SPC_ChannelOptions_specs_1 = {
	sizeof(struct ChannelOptions),
	offsetof(struct ChannelOptions, _asn_ctx),
	asn_MAP_ChannelOptions_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_ChannelOptions_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_ChannelOptions = {
	"ChannelOptions",
	"ChannelOptions",
	&asn_OP_SEQUENCE,
	asn_DEF_ChannelOptions_tags_1,
	sizeof(asn_DEF_ChannelOptions_tags_1)
		/sizeof(asn_DEF_ChannelOptions_tags_1[0]), /* 1 */
	asn_DEF_ChannelOptions_tags_1,	/* Same as above */
	sizeof(asn_DEF_ChannelOptions_tags_1)
		/sizeof(asn_DEF_ChannelOptions_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_ChannelOptions_1,
	3,	/* Elements count */
	&asn_SPC_ChannelOptions_specs_1	/* Additional specs */
};

