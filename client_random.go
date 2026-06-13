package tlsvector

func (vec *vector) parseClientRandom(off uint32) (_ uint32, err error) {
	vec.rand.Init(vec.raw, int(off), 32)
	return off + 32, err
}
