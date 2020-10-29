/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-responseInfo"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#ifndef	_VersionInfoBlock_H_
#define	_VersionInfoBlock_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <INTEGER.h>
#include <UTF8String.h>
#include <constr_SEQUENCE.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum VersionInfoBlock__Member__componentType {
	VersionInfoBlock__Member__componentType_hardware	= 0,
	VersionInfoBlock__Member__componentType_firmware	= 1,
	VersionInfoBlock__Member__componentType_software	= 2,
	VersionInfoBlock__Member__componentType_tciapp	= 3
} e_VersionInfoBlock__Member__componentType;

/* Forward definitions */
typedef struct VersionInfoBlock__Member {
	INTEGER_t	 componentType;
	UTF8String_t	 versionId;
	UTF8String_t	*releaseDate	/* OPTIONAL */;
	UTF8String_t	*description	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} VersionInfoBlock__Member;

/* VersionInfoBlock */
typedef struct VersionInfoBlock {
	A_SEQUENCE_OF(VersionInfoBlock__Member) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} VersionInfoBlock_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_VersionInfoBlock;
extern asn_SET_OF_specifics_t asn_SPC_VersionInfoBlock_specs_1;
extern asn_TYPE_member_t asn_MBR_VersionInfoBlock_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _VersionInfoBlock_H_ */
#include <asn_internal.h>
