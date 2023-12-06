/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package handler

import (
	"my5G-RANTester/test/aio5gc/context"
	"my5G-RANTester/test/aio5gc/msg"

	"github.com/free5gc/nas"
)

func RegistrationComplete(nasMsg *nas.Message, gnb *context.GNBContext, ue *context.UEContext, amf context.AMFContext) {

	nwName := amf.GetNetworkName()
	msg.SendConfigurationUpdateCommand(gnb, ue, &nwName)
}
