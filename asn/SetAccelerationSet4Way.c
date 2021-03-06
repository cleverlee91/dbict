/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-SutControl"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#include "SetAccelerationSet4Way.h"

static int
memb_longAcceleration_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= -2000 && value <= 2001)) {
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
memb_latAcceleration_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= -2000 && value <= 2001)) {
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
memb_verticalAcceleration_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= -127 && value <= 127)) {
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
memb_yawRate_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= -32767 && value <= 32767)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_memb_longAcceleration_constr_2 CC_NOTUSED = {
	{ 2, 0 }	/* (-2000..2001) */,
	-1};
static asn_oer_constraints_t asn_OER_memb_latAcceleration_constr_3 CC_NOTUSED = {
	{ 2, 0 }	/* (-2000..2001) */,
	-1};
static asn_oer_constraints_t asn_OER_memb_verticalAcceleration_constr_4 CC_NOTUSED = {
	{ 1, 0 }	/* (-127..127) */,
	-1};
static asn_oer_constraints_t asn_OER_memb_yawRate_constr_5 CC_NOTUSED = {
	{ 2, 0 }	/* (-32767..32767) */,
	-1};
asn_TYPE_member_t asn_MBR_SetAccelerationSet4Way_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SetAccelerationSet4Way, longAcceleration),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_longAcceleration_constr_2, 0,  memb_longAcceleration_constraint_1 },
		0, 0, /* No default value */
		"longAcceleration"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SetAccelerationSet4Way, latAcceleration),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_latAcceleration_constr_3, 0,  memb_latAcceleration_constraint_1 },
		0, 0, /* No default value */
		"latAcceleration"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SetAccelerationSet4Way, verticalAcceleration),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_verticalAcceleration_constr_4, 0,  memb_verticalAcceleration_constraint_1 },
		0, 0, /* No default value */
		"verticalAcceleration"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SetAccelerationSet4Way, yawRate),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_yawRate_constr_5, 0,  memb_yawRate_constraint_1 },
		0, 0, /* No default value */
		"yawRate"
		},
};
static const ber_tlv_tag_t asn_DEF_SetAccelerationSet4Way_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SetAccelerationSet4Way_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* longAcceleration */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* latAcceleration */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* verticalAcceleration */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* yawRate */
};
asn_SEQUENCE_specifics_t asn_SPC_SetAccelerationSet4Way_specs_1 = {
	sizeof(struct SetAccelerationSet4Way),
	offsetof(struct SetAccelerationSet4Way, _asn_ctx),
	asn_MAP_SetAccelerationSet4Way_tag2el_1,
	4,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_SetAccelerationSet4Way = {
	"SetAccelerationSet4Way",
	"SetAccelerationSet4Way",
	&asn_OP_SEQUENCE,
	asn_DEF_SetAccelerationSet4Way_tags_1,
	sizeof(asn_DEF_SetAccelerationSet4Way_tags_1)
		/sizeof(asn_DEF_SetAccelerationSet4Way_tags_1[0]), /* 1 */
	asn_DEF_SetAccelerationSet4Way_tags_1,	/* Same as above */
	sizeof(asn_DEF_SetAccelerationSet4Way_tags_1)
		/sizeof(asn_DEF_SetAccelerationSet4Way_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_SetAccelerationSet4Way_1,
	4,	/* Elements count */
	&asn_SPC_SetAccelerationSet4Way_specs_1	/* Additional specs */
};

