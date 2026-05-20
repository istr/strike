package container

import "testing"

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in   string
		want [3]int
		err  bool
	}{
		{"5.4.2", [3]int{5, 4, 2}, false},
		{"5.0", [3]int{5, 0, 0}, false},
		{"5", [3]int{5, 0, 0}, false},
		{"5.4.2+ds1-2", [3]int{5, 4, 2}, false},
		{"5.0.0-rc1", [3]int{5, 0, 0}, false},
		{"", [3]int{}, true},
		{"abc", [3]int{}, true},
		{"5.x.0", [3]int{5, 0, 0}, true},
	}
	for _, tc := range cases {
		got, err := parseVersion(tc.in)
		if (err != nil) != tc.err {
			t.Errorf("parseVersion(%q) err = %v, want err=%v", tc.in, err, tc.err)
			continue
		}
		if !tc.err && got != tc.want {
			t.Errorf("parseVersion(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b [3]int
		want int
	}{
		{[3]int{5, 0, 0}, [3]int{5, 0, 0}, 0},
		{[3]int{5, 0, 0}, [3]int{4, 9, 9}, 1},
		{[3]int{4, 9, 9}, [3]int{5, 0, 0}, -1},
		{[3]int{5, 4, 2}, [3]int{5, 0, 0}, 1},
	}
	for _, tc := range cases {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compareVersions(%v, %v) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
