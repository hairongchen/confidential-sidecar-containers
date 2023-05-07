// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"os/exec"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	tdxReportSize = 1024
)

type TDXAttestationReport struct {
	// version no. of this attestation report. Set to 1 for this specification.
	Version uint32 `json:"version"`
	// The guest SVN
	GuestSvn uint32 `json:"guest_svn"`
	// see table 8 - various settings
	Policy uint64 `json:"policy"`
	// as provided at launch    hex string of a 16-byte integer
	FamilyID string `json:"family_id"`
	// as provided at launch 	hex string of a 16-byte integer
	ImageID string `json:"image_id"`
	// the request VMPL for the attestation report
	VMPL          uint32 `json:"vmpl"`
	SignatureAlgo uint32 `json:"signature_algo"`
	// The install version of the firmware
	PlatformVersion uint64 `json:"platform_version"`
	// information about the platform see table 22
	PlatformInfo uint64 `json:"platform_info"`
	// 31 bits of reserved, must be zero, bottom bit indicates that the digest of the author key is present in AUTHOR_KEY_DIGEST. Set to the value of GCTX.AuthorKeyEn.
	AuthorKeyEn uint32 `json:"author_key_en"`
	// must be zero
	Reserved1 uint32 `json:"reserved1"`
	// Guest provided data.	64-byte
	ReportData string `json:"report_data"`
	// measurement calculated at launch 48-byte
	Measurement string `json:"measurement"`
	// data provided by the hypervisor at launch 32-byte
	HostData string `json:"host_data"`
	// SHA-384 digest of the ID public key that signed the ID block provided in SNP_LAUNCH_FINISH 48-byte
	IDKeyDigest string `json:"id_key_digest"`
	// SHA-384 digest of the Author public key that certified the ID key, if provided in SNP_LAUNCH_FINISH. Zeros if author_key_en is 1 (sounds backwards to me). 48-byte
	AuthorKeyDigest string `json:"author_key_digest"`
	// Report ID of this guest. 32-byte
	ReportID string `json:"report_id"`
	// Report ID of this guest's mmigration agent. 32-byte
	ReportIDMA string `json:"report_id_ma"`
	// Reported TCB version used to derive the VCEK that signed this report
	ReportedTCB uint64 `json:"reported_tcb"`
	// reserved 24-byte
	Reserved2 string `json:"reserved2"`
	// Identifier unique to the chip 64-byte
	ChipID string `json:"chip_id"`
	// The current commited SVN of the firware (version 2 report feature)
	CommittedSvn uint64 `json:"committed_svn"`
	// The current commited version of the firware
	CommittedVersion uint64 `json:"committed_version"`
	// The SVN that this guest was launched or migrated at
	LaunchSvn uint64 `json:"launch_svn"`
	// reserved 168-byte
	Reserved3 string `json:"reserved3"`
	// Signature of this attestation report. See table 23. 512-byte
	Signature string `json:"signature"`
}

func FetchTDXQuote(keyBytes []byte) (reportBytes []byte, err error) {
	runtimeData := sha256.New()
	if keyBytes != nil {
		runtimeData.Write(keyBytes)
	}

	// the get-tdx-report binary expects ReportData as the only command line attribute
	logrus.Debugf("/bin/get-tdx-quote %s", hex.EncodeToString(runtimeData.Sum(nil)))
	cmd := exec.Command("/bin/get-tdx-quote", hex.EncodeToString(runtimeData.Sum(nil)))

	reportBytesString, err := cmd.Output()
	if err != nil {
		return nil, errors.Wrapf(err, "cmd.Run() for fetching snp report failed")
	}

	// the get-tdx-report binary outputs the raw hexadecimal representation  of the report
	reportBytes = make([]byte, hex.DecodedLen(len(reportBytesString)))

	num, err := hex.Decode(reportBytes, reportBytesString)
	if err != nil {
		return nil, errors.Wrapf(err, "decoding output to hexstring failed")
	}

	if num != len(reportBytes) {
		return nil, errors.Wrapf(err, "decoding output not expected number of bytes")
	}

	return reportBytes, nil
}
