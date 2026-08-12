//go:build !parity

package agentskill

type parityTimings struct{}

func newParityTimings() *parityTimings { return &parityTimings{} }
func (*parityTimings) mark(string)     {}
func (*parityTimings) finish()         {}
