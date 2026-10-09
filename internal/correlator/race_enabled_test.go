//go:build race

package correlator

// raceEnabled reports whether the test binary carries the race detector.
// Timing ceilings scale by raceCostFactor under it: instrumentation slows the
// rule engine ~9× (wave 6.2.2 attribution: 14,4 → 127,8 µs/event on the same
// mac), so a ceiling sized for the plain build fails on the race build without
// any regression in the code.
const raceEnabled = true
