package main

// Dialogs with the phones, one cache per transport. sipgo's
// DialogServerCache and DialogClientCache give no way to set RewriteContact,
// and over TCP and TLS the requests inside a dialog (BYE, re-INVITE) must go
// into the phone's own connection: the phone listens on no port, and sipgo
// would dial its Contact. With RewriteContact sipgo sends them to the source
// of the INVITE or of the answer, and its connection pool finds the
// connection. Over UDP the Contact is used as before.

import (
	"context"
	"sync"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

type dialogCache struct {
	ua  sipgo.DialogUA
	srv sync.Map // dialog ID → *sipgo.DialogServerSession
	cli sync.Map // dialog ID → *sipgo.DialogClientSession
}

func newDialogCache(cli *sipgo.Client, contact sip.ContactHeader, rewrite bool) *dialogCache {
	return &dialogCache{ua: sipgo.DialogUA{Client: cli, ContactHDR: contact, RewriteContact: rewrite}}
}

// ReadInvite creates the dialog of a phone's INVITE; it leaves the cache when
// the dialog ends.
func (c *dialogCache) ReadInvite(req *sip.Request, tx sip.ServerTransaction) (*sipgo.DialogServerSession, error) {
	d, err := c.ua.ReadInvite(req, tx)
	if err != nil {
		return nil, err
	}
	id := d.ID
	c.srv.Store(id, d)
	go func() {
		<-d.Context().Done()
		c.srv.CompareAndDelete(id, d)
	}()
	return d, nil
}

// WriteInvite sends an INVITE to a phone; the dialog enters the cache once
// established.
func (c *dialogCache) WriteInvite(ctx context.Context, req *sip.Request) (*sipgo.DialogClientSession, error) {
	d, err := c.ua.WriteInvite(ctx, req)
	if err != nil {
		return nil, err
	}
	d.OnState(func(s sip.DialogState) {
		if s != sip.DialogStateEstablished || d.ID == "" {
			return
		}
		id := d.ID
		c.cli.Store(id, d)
		go func() {
			<-d.Context().Done()
			c.cli.CompareAndDelete(id, d)
		}()
	})
	return d, nil
}

// find returns the dialog that a request inside a dialog (re-INVITE, UPDATE,
// INFO) belongs to, when this cache holds it: its ID and the addresses the
// phone of that dialog is known by (where its INVITE came from; or where ours
// went and where its answer came from).
func (c *dialogCache) find(req *sip.Request) (id string, phone []string, ok bool) {
	if id, err := sip.DialogIDFromRequestUAS(req); err == nil {
		if v, ok := c.srv.Load(id); ok {
			return id, []string{v.(*sipgo.DialogServerSession).InviteRequest.Source()}, true
		}
	}
	if id, err := sip.DialogIDFromRequestUAC(req); err == nil {
		if v, ok := c.cli.Load(id); ok {
			d := v.(*sipgo.DialogClientSession)
			phone := []string{d.InviteRequest.Destination()}
			if d.InviteResponse != nil {
				phone = append(phone, d.InviteResponse.Source())
			}
			return id, phone, true
		}
	}
	return "", nil, false
}

// ReadAck hands the ACK to its server dialog.
func (c *dialogCache) ReadAck(req *sip.Request, tx sip.ServerTransaction) error {
	id, err := sip.DialogIDFromRequestUAS(req)
	if err != nil {
		return err
	}
	if v, ok := c.srv.Load(id); ok {
		return v.(*sipgo.DialogServerSession).ReadAck(req, tx)
	}
	return sipgo.ErrDialogDoesNotExists
}

// ReadBye hands the BYE to its dialog, ours as server or as client.
func (c *dialogCache) ReadBye(req *sip.Request, tx sip.ServerTransaction) error {
	if id, err := sip.DialogIDFromRequestUAS(req); err == nil {
		if v, ok := c.srv.Load(id); ok {
			return v.(*sipgo.DialogServerSession).ReadBye(req, tx)
		}
	}
	if id, err := sip.DialogIDFromRequestUAC(req); err == nil {
		if v, ok := c.cli.Load(id); ok {
			return v.(*sipgo.DialogClientSession).ReadBye(req, tx)
		}
	}
	return sipgo.ErrDialogDoesNotExists
}
