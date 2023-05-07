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
	//TODO
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
