/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-CommonTypes"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#include "ResultCode.h"

/*
 * This type is implemented using ENUMERATED,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_ResultCode_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static const asn_INTEGER_enum_map_t asn_MAP_ResultCode_value2enum_1[] = {
	{ 0,	9,	"rcSuccess" },
	{ 1,	9,	"rcFailure" }
};
static const unsigned int asn_MAP_ResultCode_enum2value_1[] = {
	1,	/* rcFailure(1) */
	0	/* rcSuccess(0) */
};
const asn_INTEGER_specifics_t asn_SPC_ResultCode_specs_1 = {
	asn_MAP_ResultCode_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_ResultCode_enum2value_1,	/* N => "tag"; sorted by N */
	2,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_ResultCode_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_ResultCode = {
	"ResultCode",
	"ResultCode",
	&asn_OP_ENUMERATED,
	asn_DEF_ResultCode_tags_1,
	sizeof(asn_DEF_ResultCode_tags_1)
		/sizeof(asn_DEF_ResultCode_tags_1[0]), /* 1 */
	asn_DEF_ResultCode_tags_1,	/* Same as above */
	sizeof(asn_DEF_ResultCode_tags_1)
		/sizeof(asn_DEF_ResultCode_tags_1[0]), /* 1 */
	{ &asn_OER_type_ResultCode_constr_1, 0, ENUMERATED_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_ResultCode_specs_1	/* Additional specs */
};

