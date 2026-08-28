// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package peerauth

import "testing"

// A realistic /proc/<pid>/stat body. The fields after the (comm) field are, in
// order: state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt
// cmajflt utime stime cutime cstime priority nice num_threads itrealvalue
// starttime ... so the 20th token after comm (index 19) is starttime.
const (
	statSimple = "1234 (bash) S 1 1234 1234 34816 1234 4194560 100 0 0 0 5 2 0 0 20 0 1 0 8967 0 0"
	// comm here contains both a space and a close-paren, exercising the
	// anchor-on-last-paren rule.
	statTrickyComm = "4242 (weird ) name) R 1 4242 4242 0 -1 4194304 10 0 0 0 1 1 0 0 20 0 2 0 55123 0 0"
)

func TestParseStartTime(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    uint64
		wantErr bool
	}{
		{name: "simple", content: statSimple, want: 8967},
		{name: "comm with space and paren", content: statTrickyComm, want: 55123},
		{name: "no comm parens", content: "1234 bash S 1 2 3", wantErr: true},
		{name: "too few fields after comm", content: "1234 (bash) S 1 2 3", wantErr: true},
		{
			name:    "non-numeric starttime",
			content: "1234 (bash) S 1 1234 1234 34816 1234 4194560 100 0 0 0 5 2 0 0 20 0 1 0 notanumber 0 0",
			wantErr: true,
		},
		{name: "empty", content: "", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseStartTime(tc.content)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got start-time %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("want start-time %d, got %d", tc.want, got)
			}
		})
	}
}
