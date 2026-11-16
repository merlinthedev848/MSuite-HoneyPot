package mikrotik

import (
	"bufio"
	"fmt"
	"io"
)

// RouterOS binary API word-length encoding.
// https://help.mikrotik.com/docs/spaces/ROS/pages/47579160/API
//
//	< 0x80          1 byte
//	< 0x4000        2 bytes, high bit set
//	< 0x200000      3 bytes
//	< 0x10000000    4 bytes
//	otherwise       0xF0 plus 4 byte length

func encodeLength(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x4000:
		return []byte{byte(n>>8) | 0x80, byte(n)}
	case n < 0x200000:
		return []byte{byte(n>>16) | 0xC0, byte(n >> 8), byte(n)}
	case n < 0x10000000:
		return []byte{byte(n>>24) | 0xE0, byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		return []byte{0xF0, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func readLen(r io.Reader) (int, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	c := b[0]
	switch {
	case c&0x80 == 0x00:
		return int(c), nil
	case c&0xC0 == 0x80:
		var rest [1]byte
		if _, err := io.ReadFull(r, rest[:]); err != nil {
			return 0, err
		}
		return int(c&0x3F)<<8 | int(rest[0]), nil
	case c&0xE0 == 0xC0:
		var rest [2]byte
		if _, err := io.ReadFull(r, rest[:]); err != nil {
			return 0, err
		}
		return int(c&0x1F)<<16 | int(rest[0])<<8 | int(rest[1]), nil
	case c&0xF0 == 0xE0:
		var rest [3]byte
		if _, err := io.ReadFull(r, rest[:]); err != nil {
			return 0, err
		}
		return int(c&0x0F)<<24 | int(rest[0])<<16 | int(rest[1])<<8 | int(rest[2]), nil
	case c&0xF8 == 0xF0:
		var rest [4]byte
		if _, err := io.ReadFull(r, rest[:]); err != nil {
			return 0, err
		}
		return int(rest[0])<<24 | int(rest[1])<<16 | int(rest[2])<<8 | int(rest[3]), nil
	default:
		return 0, fmt.Errorf("invalid routeros api length prefix 0x%02x", c)
	}
}

func writeSentence(w io.Writer, words []string) error {
	for _, word := range words {
		if _, err := w.Write(encodeLength(len(word))); err != nil {
			return err
		}
		if _, err := io.WriteString(w, word); err != nil {
			return err
		}
	}
	_, err := w.Write([]byte{0})
	return err
}

func readSentence(r io.Reader) ([]string, error) {
	var words []string
	for {
		n, err := readLen(r)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return words, nil
		}
		if n > 16*1024*1024 {
			return nil, fmt.Errorf("routeros api word too large (%d bytes)", n)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		words = append(words, string(buf))
	}
}

type sentence struct {
	kind  string
	attrs map[string]string
}

type reply struct {
	records []map[string]string
	done    map[string]string
	trap    string
}

func parseAttribute(word string) (string, string, bool) {
	if len(word) == 0 || word[0] != '=' {
		return "", "", false
	}
	body := word[1:]
	for i := 0; i < len(body); i++ {
		if body[i] == '=' {
			return body[:i], body[i+1:], true
		}
	}
	return body, "", true
}

func readReply(r io.Reader) (*reply, error) {
	out := &reply{}
	for {
		words, err := readSentence(r)
		if err != nil {
			return nil, err
		}
		if len(words) == 0 {
			continue
		}
		s := sentence{kind: words[0], attrs: make(map[string]string)}
		for _, w := range words[1:] {
			if k, v, ok := parseAttribute(w); ok {
				s.attrs[k] = v
			}
		}
		switch s.kind {
		case "!re":
			out.records = append(out.records, s.attrs)
		case "!trap":
			msg := s.attrs["message"]
			if msg == "" {
				msg = "unknown trap"
			}
			if out.trap == "" {
				out.trap = msg
			} else {
				out.trap += "; " + msg
			}
		case "!fatal":
			msg := s.attrs["message"]
			if msg == "" {
				msg = "fatal api error"
			}
			return nil, fmt.Errorf("mikrotik api fatal: %s", msg)
		case "!done":
			out.done = s.attrs
			return out, nil
		}
	}
}

func run(r io.Reader, w io.Writer, words ...string) (*reply, error) {
	if err := writeSentence(w, words); err != nil {
		return nil, err
	}
	if f, ok := w.(interface{ Flush() error }); ok {
		if err := f.Flush(); err != nil {
			return nil, err
		}
	}
	return readReply(r)
}

type stream struct {
	r *bufio.Reader
	w *bufio.Writer
}

func newStream(rw io.ReadWriter) *stream {
	return &stream{r: bufio.NewReader(rw), w: bufio.NewWriter(rw)}
}
