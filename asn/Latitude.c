/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IEEE-1609-3-WEE"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#include "Latitude.h"

static int
memb_fill_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	if(st->size > 0) {
		/* Size in bits */
		size = 8 * st->size - (st->bits_unused & 0x07);
	} else {
		size = 0;
	}
	
	if((size == 1)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_lat_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= -900000000 && value <= 900000001)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_memb_fill_constr_2 CC_NOTUSED = {
	{ 0, 0 },
	1	/* (SIZE(1..1)) */};
static asn_oer_constraints_t asn_OER_memb_lat_constr_3 CC_NOTUSED = {
	{ 4, 0 }	/* (-900000000..900000001) */,
	-1};
asn_TYPE_member_t asn_MBR_Latitude_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct Latitude, fill),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		0,
		{ &asn_OER_memb_fill_constr_2, 0,  memb_fill_constraint_1 },
		0, 0, /* No default value */
		"fill"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Latitude, lat),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_lat_constr_3, 0,  memb_lat_constraint_1 },
		0, 0, /* No default value */
		"lat"
		},
};
static const ber_tlv_tag_t asn_DEF_Latitude_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_Latitude_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* fill */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* lat */
};
asn_SEQUENCE_specifics_t asn_SPC_Latitude_specs_1 = {
	sizeof(struct Latitude),
	offsetof(struct Latitude, _asn_ctx),
	asn_MAP_Latitude_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_Latitude = {
	"Latitude",
	"Latitude",
	&asn_OP_SEQUENCE,
	asn_DEF_Latitude_tags_1,
	sizeof(asn_DEF_Latitude_tags_1)
		/sizeof(asn_DEF_Latitude_tags_1[0]), /* 1 */
	asn_DEF_Latitude_tags_1,	/* Same as above */
	sizeof(asn_DEF_Latitude_tags_1)
		/sizeof(asn_DEF_Latitude_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_Latitude_1,
	2,	/* Elements count */
	&asn_SPC_Latitude_specs_1	/* Additional specs */
};

