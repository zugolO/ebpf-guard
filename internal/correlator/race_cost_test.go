package correlator

// raceCostFactor is the slowdown the race detector puts on the rule engine,
// rounded up from the measured ~9× (race_enabled_test.go). Timing ceilings
// multiply by it only when raceEnabled is true.
const raceCostFactor = 10
