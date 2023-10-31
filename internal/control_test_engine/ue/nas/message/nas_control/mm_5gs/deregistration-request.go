package mm_5gs

import (
	"bytes"
	"fmt"
	"my5G-RANTester/internal/control_test_engine/ue/context"

	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
)

func GetDeregistrationRequest(ue *context.UEContext) (nasPdu []byte) {
	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeDeregistrationRequestUEOriginatingDeregistration)

	deregistrationRequest := nasMessage.NewDeregistrationRequestUEOriginatingDeregistration(0)

	deregistrationRequest.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	deregistrationRequest.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	deregistrationRequest.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0x00)
	deregistrationRequest.SetSwitchOff(1)
	deregistrationRequest.SetReRegistrationRequired(0)
	deregistrationRequest.SetAccessType(1)
	deregistrationRequest.DeregistrationRequestMessageIdentity.SetMessageType(nas.MsgTypeDeregistrationRequestUEOriginatingDeregistration)
	deregistrationRequest.NgksiAndDeregistrationType.SetTSC(nasMessage.TypeOfSecurityContextFlagNative)
	deregistrationRequest.NgksiAndDeregistrationType.SetNasKeySetIdentifiler(ue.GetUeId())
	deregistrationRequest.MobileIdentity5GS = ue.GetSuci()

	m.GmmMessage.DeregistrationRequestUEOriginatingDeregistration = deregistrationRequest

	data := new(bytes.Buffer)
	err := m.GmmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	nasPdu = data.Bytes()
	return
}
