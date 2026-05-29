package tlsvector

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type stage struct {
	key string

	origin   []byte
	flows    [][]byte
	chfmt    []byte
	chjson   []byte
	shfmt    []byte
	ja3, ja4 []byte
}

var (
	stages    []stage
	stagesReg = map[string]int{}
)

func init() {
	var (
		reFlow    = regexp.MustCompile(`>>> Flow (\d+).*`)
		rePayload = regexp.MustCompile(`^\S+\s+((?:[0-9a-fA-F]{2}\s+)*[0-9a-fA-F]{2})`)
		ps        = string(os.PathSeparator)
	)

	_ = filepath.Walk("testdata", func(path string, info os.FileInfo, err error) error {
		if info.IsDir() && path != "testdata" {
			rawfp := fmt.Sprintf("%s%sraw.txt", path, ps)

			st := stage{flows: make([][]byte, 15)}
			st.key = filepath.Base(path)
			st.origin, _ = os.ReadFile(rawfp)

			buf := make([]byte, 0, 1024)
			rdr := bytes.NewReader(st.origin)
			scr := bufio.NewScanner(rdr)
			var flowID int64 = -1
			for scr.Scan() {
				line := scr.Bytes()
				if m := reFlow.FindSubmatch(line); len(m) > 0 {
					if flowID >= 0 {
						st.flows[flowID] = append(st.flows[flowID], buf...)
						buf = buf[:0]
					}
					if flowID, err = strconv.ParseInt(string(m[1]), 10, 64); err != nil {
						panic(err)
					}
					flowID--
					continue
				}
				if m := rePayload.FindSubmatch(line); len(m) > 0 {
					pl := m[1]
					for len(pl) > 0 {
						p2 := pl[:2]
						pl = pl[2:]
						b2, err := strconv.ParseInt(string(p2), 16, 64)
						if err != nil {
							panic(err)
						}
						buf = append(buf, byte(b2))
						pl = bytes.TrimLeft(pl, " ")
					}
					continue
				}
				panic(fmt.Sprintf("wring line format: %s", string(line)))
			}

			if len(buf) > 0 {
				st.flows[flowID] = append(st.flows[flowID], buf...)
			}

			st.chfmt, _ = os.ReadFile(fmt.Sprintf("%s%sclient_hello.fmt.txt", path, ps))
			st.chjson, _ = os.ReadFile(fmt.Sprintf("%s%sclient_hello.json", path, ps))
			st.shfmt, _ = os.ReadFile(fmt.Sprintf("%s%sserver_hello.fmt.txt", path, ps))
			st.ja3, _ = os.ReadFile(fmt.Sprintf("%s%sclient_hello.ja3.txt", path, ps))
			st.ja4, _ = os.ReadFile(fmt.Sprintf("%s%sclient_hello.ja4.txt", path, ps))
			stages = append(stages, st)
			stagesReg[st.key] = len(stages) - 1
			return nil
		}
		return nil
	})
}

func getStage(key string) *stage {
	i, ok := stagesReg[key]
	if !ok {
		return nil
	}
	return &stages[i]
}

func getTBName(tb testing.TB) string {
	key := tb.Name()
	return key[strings.Index(key, "/")+1:]
}
