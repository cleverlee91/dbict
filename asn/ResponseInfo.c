/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-responseInfo"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#include "ResponseInfo.h"

asn_TYPE_member_t asn_MBR_ResponseInfo_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct ResponseInfo, msgID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MsgID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"msgID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct ResponseInfo, resultCode),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ResultCode,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"resultCode"
		},
	{ ATF_POINTER, 2, offsetof(struct ResponseInfo, info),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_InfoContent,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"info"
		},
	{ ATF_POINTER, 1, offsetof(struct ResponseInfo, exception),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Exception,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"exception"
		},
};
static const int asn_MAP_ResponseInfo_oms_1[] = { 2, 3 };
static const ber_tlv_tag_t asn_DEF_ResponseInfo_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_ResponseInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* msgID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* resultCode */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* info */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* exception */
};
asn_SEQUENCE_specifics_t asn_SPC_ResponseInfo_specs_1 = {
	sizeof(struct ResponseInfo),
	offsetof(struct ResponseInfo, _asn_ctx),
	asn_MAP_ResponseInfo_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_ResponseInfo_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	4,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_ResponseInfo = {
	"ResponseInfo",
	"ResponseInfo",
	&asn_OP_SEQUENCE,
	asn_DEF_ResponseInfo_tags_1,
	sizeof(asn_DEF_ResponseInfo_tags_1)
		/sizeof(asn_DEF_ResponseInfo_tags_1[0]), /* 1 */
	asn_DEF_ResponseInfo_tags_1,	/* Same as above */
	sizeof(asn_DEF_ResponseInfo_tags_1)
		/sizeof(asn_DEF_ResponseInfo_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_ResponseInfo_1,
	4,	/* Elements count */
	&asn_SPC_ResponseInfo_specs_1	/* Additional specs */
};

