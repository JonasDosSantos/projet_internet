package p2p

import (
	"encoding/binary"
	"fmt"
)

// types des messages en accords avec le sujet
const (
	TypePing                 = 0
	TypeHello                = 1
	TypeRootRequest          = 2
	TypeDatumRequest         = 3
	TypeNatTraversalRequest  = 4
	TypeNatTraversalRequest2 = 5

	TypeOk         = 128
	Error          = 129
	TypeHelloReply = 130
	TypeRootReply  = 131
	TypeDatum      = 132
	TypeNoDatum    = 133

	TypeKeyExchange = 20

	ExtensionNAT        = 1
	ExtensionEncryption = 2
)

// structure des messages UDP
type Message struct {
	Id        uint32
	Type      uint8
	Length    uint16
	Body      []byte
	Signature []byte
}

// Pour transformer un message (struct Message) en message (chaine d'octets en binaire)
func (m *Message) Serialize() []byte {

	// Id + Type + Length = 7 octets
	// donc le message fait bien 7 + len(Body) + 64 (signature)
	totalSize := 7 + len(m.Body)
	if len(m.Signature) != 0 {
		totalSize += 64
	}

	data := make([]byte, totalSize)

	// ecriture de l'ID
	binary.BigEndian.PutUint32(data[0:4], m.Id)

	// ecriture du Type
	data[4] = m.Type

	// Ecriture de Length
	binary.BigEndian.PutUint16(data[5:7], uint16(len(m.Body)))

	// ecriture du body
	copy(data[7:], m.Body)

	// ecriture de la signature
	if len(m.Signature) != 0 {
		copy(data[7+len(m.Body):], m.Signature)
	}

	return data
}

// Transformation inverse (chaine d'octets en bianire) to (struct Message)
func Deserialize(data []byte) (*Message, error) {
	if len(data) < 7 {
		return nil, fmt.Errorf("pas assez d'octets")
	}

	// on récupère le "header" du message
	id := binary.BigEndian.Uint32(data[0:4])
	msgType := data[4]
	bodyLen := binary.BigEndian.Uint16(data[5:7])

	// on vérifie que la tailel du body est bien celle prévue
	if len(data) < 7+int(bodyLen) {
		return nil, fmt.Errorf("message incomplet")
	}

	// on récupère le body
	body := make([]byte, bodyLen)
	copy(body, data[7:7+bodyLen])

	// on récupère la signature
	var signature []byte
	if len(data) >= 7+int(bodyLen)+64 {
		signature = make([]byte, 64)
		copy(signature, data[7+int(bodyLen):7+int(bodyLen)+64])
	}

	// tout ce qui vient après la signature est ignoré

	return &Message{
		Id:        id,
		Type:      msgType,
		Length:    bodyLen,
		Body:      body,
		Signature: signature,
	}, nil
}

// fonction pour convertir le type d'un message en string
func msg__type__to__string(msgType uint8) string {
	switch msgType {
	case TypePing:
		return "Ping"
	case TypeOk:
		return "Ok"
	case TypeHello:
		return "Hello"
	case TypeHelloReply:
		return "HelloReply"
	case Error:
		return "Error"
	case TypeRootRequest:
		return "RootRequest"
	case TypeRootReply:
		return "RootReply"
	case TypeDatumRequest:
		return "DatumRequest"
	case TypeDatum:
		return "Datum"
	case TypeNoDatum:
		return "NoDatum"
	case TypeNatTraversalRequest:
		return "NatTraversalRequest"
	case TypeNatTraversalRequest2:
		return "NatTraversalRequest2"
	default:
		return fmt.Sprintf("Unknown(%d)", msgType)
	}
}
