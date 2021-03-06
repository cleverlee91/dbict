/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-CommonTypes"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#include "ExceptionType.h"

/*
 * This type is implemented using ENUMERATED,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_ExceptionType_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static const asn_INTEGER_enum_map_t asn_MAP_ExceptionType_value2enum_1[] = {
	{ 0,	4,	"info" },
	{ 1,	7,	"warning" },
	{ 2,	5,	"error" }
};
static const unsigned int asn_MAP_ExceptionType_enum2value_1[] = {
	2,	/* error(2) */
	0,	/* info(0) */
	1	/* warning(1) */
};
const asn_INTEGER_specifics_t asn_SPC_ExceptionType_specs_1 = {
	asn_MAP_ExceptionType_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_ExceptionType_enum2value_1,	/* N => "tag"; sorted by N */
	3,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_ExceptionType_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_ExceptionType = {
	"ExceptionType",
	"ExceptionType",
	&asn_OP_ENUMERATED,
	asn_DEF_ExceptionType_tags_1,
	sizeof(asn_DEF_ExceptionType_tags_1)
		/sizeof(asn_DEF_ExceptionType_tags_1[0]), /* 1 */
	asn_DEF_ExceptionType_tags_1,	/* Same as above */
	sizeof(asn_DEF_ExceptionType_tags_1)
		/sizeof(asn_DEF_ExceptionType_tags_1[0]), /* 1 */
	{ &asn_OER_type_ExceptionType_constr_1, 0, ENUMERATED_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_ExceptionType_specs_1	/* Additional specs */
};

