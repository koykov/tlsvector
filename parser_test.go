package tlsvector

import (
	"bytes"
	"testing"
)

func TestParser(t *testing.T) {
	for i := 0; i < len(stages); i++ {
		st := &stages[i]
		t.Run(st.key, func(t *testing.T) {
			t.Run("client hello", func(t *testing.T) {
				vec := New()
				err := vec.Parse(st.flows[0])
				if err != nil {
					t.Fatal(err)
				}
				js := vec.JSON()
				if !bytes.Equal([]byte(js), st.chjson) {
					t.Errorf("mismatch result and expectation")
				}
				s := vec.String()
				if !bytes.Equal([]byte(s), st.chfmt) {
					t.Errorf("mismatch result and expectation")
				}
			})
			t.Run("server hello", func(t *testing.T) {
				if len(st.shfmt) == 0 {
					t.Skip()
				}
				vec := New()
				err := vec.Parse(st.flows[1])
				if err != nil {
					t.Fatal(err)
				}
				s := vec.String()
				if !bytes.Equal([]byte(s), st.shfmt) {
					t.Errorf("mismatch result and expectation")
				}
			})
		})
	}
}

func BenchmarkParser(b *testing.B) {
	benchfn := func(b *testing.B, st *stage, flowID int) {
		vec := New()
		b.SetBytes(int64(len(st.flows[flowID])))
		b.ReportAllocs()
		b.ResetTimer()
		for j := 0; j < b.N; j++ {
			vec.Reset()
			_ = vec.Parse(st.flows[flowID])
		}
	}
	for i := 0; i < len(stages); i++ {
		st := &stages[i]
		b.Run(st.key, func(b *testing.B) {
			b.Run("client hello", func(b *testing.B) { benchfn(b, st, 0) })
			b.Run("server hello", func(b *testing.B) { benchfn(b, st, 1) })
		})
	}
}
