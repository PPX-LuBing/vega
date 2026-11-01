package main

import "testing"

func TestStatsCodec(t *testing.T) {
	stat := appendString(nil, 1, "user>>>alice>>>traffic>>>uplink")
	stat = appendTag(stat, 2, 0)
	stat = appendVarint(stat, 123)
	response := appendTag(nil, 1, 2)
	response = appendVarint(response, uint64(len(stat)))
	response = append(response, stat...)
	got, err := parseQueryStatsResponse(response)
	if err != nil || got["user>>>alice>>>traffic>>>uplink"] != 123 {
		t.Fatalf("%v %v", got, err)
	}
	for _, input := range [][]byte{
		{0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01},
		{0x0a, 0x03, 0x0a, 0xff, 0x7f},
		{0x0a, 0x08},
		{0x12, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	} {
		if _, err := parseQueryStatsResponse(input); err == nil {
			t.Fatalf("accepted malformed input %x", input)
		}
	}
}

func FuzzStatsResponse(f *testing.F) {
	f.Add([]byte{0x0a, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = parseQueryStatsResponse(data) })
}
