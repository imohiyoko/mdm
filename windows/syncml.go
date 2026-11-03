package windows

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
)

// OMA-DM（SyncML 1.2）のメッセージ。Windows の MDM の端末とのやり取りに使う。

type locURI struct {
	LocURI string `xml:"LocURI"`
}

type syncMeta struct {
	Format string `xml:"syncml:metinf Format,omitempty"`
	Type   string `xml:"syncml:metinf Type,omitempty"`
}

type syncItem struct {
	Source *locURI    `xml:"Source,omitempty"`
	Target *locURI    `xml:"Target,omitempty"`
	Meta   *syncMeta  `xml:"Meta,omitempty"`
	Data   *innerData `xml:"Data,omitempty"`
}

// innerData は Data の中身。XML のこともあるので、そのまま読み書きする。
type innerData struct {
	Inner string `xml:",innerxml"`
}

// text は Data の文字（XML の実体参照を戻す）。
func (d *innerData) text() string {
	if d == nil {
		return ""
	}
	var s string
	if err := xml.Unmarshal([]byte("<d>"+d.Inner+"</d>"), &s); err != nil {
		return d.Inner
	}
	return s
}

// syncCmd はコマンド（Alert・Get・Replace・Status・Results など）。
type syncCmd struct {
	XMLName xml.Name
	CmdID   string     `xml:"CmdID"`
	MsgRef  string     `xml:"MsgRef,omitempty"`
	CmdRef  string     `xml:"CmdRef,omitempty"`
	Cmd     string     `xml:"Cmd,omitempty"`
	Data    *innerData `xml:"Data,omitempty"`
	Items   []syncItem `xml:"Item"`
}

type syncHdr struct {
	VerDTD    string  `xml:"VerDTD"`
	VerProto  string  `xml:"VerProto"`
	SessionID string  `xml:"SessionID"`
	MsgID     string  `xml:"MsgID"`
	Target    *locURI `xml:"Target"`
	Source    *locURI `xml:"Source"`
}

type syncBody struct {
	Cmds  []syncCmd `xml:",any"`
	Final *struct{} `xml:"Final"`
}

type syncML struct {
	XMLName xml.Name `xml:"SyncML"`
	Xmlns   string   `xml:"xmlns,attr,omitempty"`
	Hdr     syncHdr  `xml:"SyncHdr"`
	Body    syncBody `xml:"SyncBody"`
}

func parseSyncML(b []byte) (*syncML, error) {
	var m syncML
	if err := xml.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("windows: SyncML が読めない: %w", err)
	}
	// Final は ",any" にも入るので除く。
	cmds := m.Body.Cmds[:0]
	for _, c := range m.Body.Cmds {
		if c.XMLName.Local != "Final" {
			cmds = append(cmds, c)
		}
	}
	m.Body.Cmds = cmds
	return &m, nil
}

// reply は端末への答えを組み立てる。
type reply struct {
	in     *syncML
	server string
	cmds   []syncCmd
	nextID int
}

func newReply(in *syncML, serverURL string) *reply {
	r := &reply{in: in, server: serverURL, nextID: 1}
	// SyncHdr への答え。
	r.status("0", "SyncHdr", "200")
	return r
}

func (r *reply) id() string {
	id := strconv.Itoa(r.nextID)
	r.nextID++
	return id
}

func (r *reply) status(cmdRef, cmd, code string) {
	r.cmds = append(r.cmds, syncCmd{XMLName: xml.Name{Local: "Status"}, CmdID: r.id(), MsgRef: r.in.Hdr.MsgID, CmdRef: cmdRef, Cmd: cmd, Data: &innerData{Inner: code}})
}

// command は端末へのコマンドを足す。CmdID は待ち行列の ID にして、答えと結びつける。
func (r *reply) command(c syncCmd) {
	r.cmds = append(r.cmds, c)
}

// hasCommands は状態の答え以外のコマンドがあるか。無ければ端末はやり取りを終える。
func (r *reply) hasCommands() bool {
	for _, c := range r.cmds {
		if c.XMLName.Local != "Status" {
			return true
		}
	}
	return false
}

func (r *reply) bytes() []byte {
	out := syncML{
		Xmlns: "SYNCML:SYNCML1.2",
		Hdr: syncHdr{
			VerDTD: "1.2", VerProto: "DM/1.2", SessionID: r.in.Hdr.SessionID, MsgID: r.in.Hdr.MsgID,
			Target: r.in.Hdr.Source, Source: &locURI{LocURI: r.server},
		},
		Body: syncBody{Cmds: r.cmds, Final: &struct{}{}},
	}
	var b bytes.Buffer
	enc := xml.NewEncoder(&b)
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
	return b.Bytes()
}

// commandCmd は待ち行列の命令を SyncML のコマンドにする。
func commandCmd(cmdID, verb, uri, format, data string) syncCmd {
	it := syncItem{Target: &locURI{LocURI: uri}}
	if format != "" {
		it.Meta = &syncMeta{Format: format}
	}
	if verb != "Get" && verb != "Delete" {
		var b bytes.Buffer
		if format == "xml" {
			b.WriteString(data) // XML はそのまま入れる
		} else {
			_ = xml.EscapeText(&b, []byte(data))
		}
		it.Data = &innerData{Inner: b.String()}
	}
	return syncCmd{XMLName: xml.Name{Local: verb}, CmdID: cmdID, Items: []syncItem{it}}
}
