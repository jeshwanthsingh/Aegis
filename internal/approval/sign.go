package approval

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"aegis/internal/dsse"
)

type LocalIssuer struct {
	PrivateKey ed25519.PrivateKey
}

func (i LocalIssuer) Issue(_ context.Context, payload Ticket) (SignedTicket, error) {
	return SignTicket(payload, i.PrivateKey)
}

func SignTicket(payload Ticket, privateKey ed25519.PrivateKey) (SignedTicket, error) {
	statement := Statement{
		Type:          dsse.StatementType,
		Subject:       []dsse.StatementSubject{},
		PredicateType: TicketPredicateType,
		Predicate:     payload,
	}
	statementBytes, err := json.Marshal(statement)
	if err != nil {
		return SignedTicket{}, fmt.Errorf("marshal approval ticket statement: %w", err)
	}
	envelope, err := dsse.SignEnvelope(dsse.PayloadType, statementBytes, privateKey)
	if err != nil {
		return SignedTicket{}, err
	}
	return SignedTicket{Envelope: envelope, Statement: statement}, nil
}
