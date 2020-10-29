/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "TCI-indication"
 * 	found in "TCI.asn1"
 * 	`asn1c -no-gen-PER -fcompound-names -fwide-types`
 */

#include "SecurityResultCode.h"

/*
 * This type is implemented using ENUMERATED,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_SecurityResultCode_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static const asn_INTEGER_enum_map_t asn_MAP_SecurityResultCode_value2enum_1[] = {
	{ 0,	8,	"reserved" },
	{ 1,	7,	"success" },
	{ 2,	27,	"inconsistentInputParameters" },
	{ 3,	23,	"spduParsingInvalidInput" },
	{ 4,	46,	"spduParsingUnsupportedCriticalInformationField" },
	{ 5,	30,	"spduParsingCertificateNotFound" },
	{ 6,	37,	"spduParsingGenerationTimeNotAvailable" },
	{ 7,	41,	"spduParsingGenerationLocationNotAvailable" },
	{ 8,	56,	"spduCertificateChainNotEnoughInformationToConstructChain" },
	{ 9,	45,	"spduCertificateChainChainEndedAtUntrustedRoot" },
	{ 10,	52,	"spduCertificateChainChainWasTooLongForImplementation" },
	{ 11,	38,	"spduCertificateChainCertificateRevoked" },
	{ 12,	30,	"spduCertificateChainOverdueCRL" },
	{ 13,	43,	"spduCertificateChainInconsistentExpiryTimes" },
	{ 14,	42,	"spduCertificateChainInconsistentStartTimes" },
	{ 15,	48,	"spduCertificateChainInconsistentChainPermissions" },
	{ 16,	29,	"spduCryptoVerificationFailure" },
	{ 17,	48,	"spduConsistencyFutureCertificateAtGenerationTime" },
	{ 18,	49,	"spduConsistencyExpiredCertificateAtGenerationTime" },
	{ 19,	33,	"spduConsistencyExpiryDateTooEarly" },
	{ 20,	32,	"spduConsistencyExpiryDateTooLate" },
	{ 21,	54,	"spduConsistencyGenerationLocationOutsideValidityRegion" },
	{ 22,	35,	"spduConsistencyNoGenerationLocation" },
	{ 23,	31,	"spduConsistencyUnauthorizedPSID" },
	{ 24,	53,	"spduInternalConsistencyExpiryTimeBeforeGenerationTime" },
	{ 25,	45,	"spduInternalConsistencyextDataHashDoesntMatch" },
	{ 26,	44,	"spduInternalConsistencynoExtDataHashProvided" },
	{ 27,	43,	"spduInternalConsistencynoExtDataHashPresent" },
	{ 28,	34,	"spduLocalConsistencyPSIDsDontMatch" },
	{ 29,	42,	"spduLocalConsistencyChainWasTooLongForSDEE" },
	{ 30,	39,	"spduRelevanceGenerationTimeTooFarInPast" },
	{ 31,	41,	"spduRelevanceGenerationTimeTooFarInFuture" },
	{ 32,	29,	"spduRelevanceExpiryTimeInPast" },
	{ 33,	41,	"spduRelevanceGenerationLocationTooDistant" },
	{ 34,	25,	"spduRelevanceReplayedSpdu" },
	{ 35,	22,	"spduCertificateExpired" }
};
static const unsigned int asn_MAP_SecurityResultCode_enum2value_1[] = {
	2,	/* inconsistentInputParameters(2) */
	0,	/* reserved(0) */
	11,	/* spduCertificateChainCertificateRevoked(11) */
	9,	/* spduCertificateChainChainEndedAtUntrustedRoot(9) */
	10,	/* spduCertificateChainChainWasTooLongForImplementation(10) */
	15,	/* spduCertificateChainInconsistentChainPermissions(15) */
	13,	/* spduCertificateChainInconsistentExpiryTimes(13) */
	14,	/* spduCertificateChainInconsistentStartTimes(14) */
	8,	/* spduCertificateChainNotEnoughInformationToConstructChain(8) */
	12,	/* spduCertificateChainOverdueCRL(12) */
	35,	/* spduCertificateExpired(35) */
	18,	/* spduConsistencyExpiredCertificateAtGenerationTime(18) */
	19,	/* spduConsistencyExpiryDateTooEarly(19) */
	20,	/* spduConsistencyExpiryDateTooLate(20) */
	17,	/* spduConsistencyFutureCertificateAtGenerationTime(17) */
	21,	/* spduConsistencyGenerationLocationOutsideValidityRegion(21) */
	22,	/* spduConsistencyNoGenerationLocation(22) */
	23,	/* spduConsistencyUnauthorizedPSID(23) */
	16,	/* spduCryptoVerificationFailure(16) */
	24,	/* spduInternalConsistencyExpiryTimeBeforeGenerationTime(24) */
	25,	/* spduInternalConsistencyextDataHashDoesntMatch(25) */
	27,	/* spduInternalConsistencynoExtDataHashPresent(27) */
	26,	/* spduInternalConsistencynoExtDataHashProvided(26) */
	29,	/* spduLocalConsistencyChainWasTooLongForSDEE(29) */
	28,	/* spduLocalConsistencyPSIDsDontMatch(28) */
	5,	/* spduParsingCertificateNotFound(5) */
	7,	/* spduParsingGenerationLocationNotAvailable(7) */
	6,	/* spduParsingGenerationTimeNotAvailable(6) */
	3,	/* spduParsingInvalidInput(3) */
	4,	/* spduParsingUnsupportedCriticalInformationField(4) */
	32,	/* spduRelevanceExpiryTimeInPast(32) */
	33,	/* spduRelevanceGenerationLocationTooDistant(33) */
	31,	/* spduRelevanceGenerationTimeTooFarInFuture(31) */
	30,	/* spduRelevanceGenerationTimeTooFarInPast(30) */
	34,	/* spduRelevanceReplayedSpdu(34) */
	1	/* success(1) */
};
const asn_INTEGER_specifics_t asn_SPC_SecurityResultCode_specs_1 = {
	asn_MAP_SecurityResultCode_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_SecurityResultCode_enum2value_1,	/* N => "tag"; sorted by N */
	36,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_SecurityResultCode_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_SecurityResultCode = {
	"SecurityResultCode",
	"SecurityResultCode",
	&asn_OP_ENUMERATED,
	asn_DEF_SecurityResultCode_tags_1,
	sizeof(asn_DEF_SecurityResultCode_tags_1)
		/sizeof(asn_DEF_SecurityResultCode_tags_1[0]), /* 1 */
	asn_DEF_SecurityResultCode_tags_1,	/* Same as above */
	sizeof(asn_DEF_SecurityResultCode_tags_1)
		/sizeof(asn_DEF_SecurityResultCode_tags_1[0]), /* 1 */
	{ &asn_OER_type_SecurityResultCode_constr_1, 0, ENUMERATED_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_SecurityResultCode_specs_1	/* Additional specs */
};

