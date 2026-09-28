package db

// Statement accessors for the planner-pin tests in db_test (the
// package's own tests would see the constants; the external test
// package keeps the real-migration schema through dbtest).
func RollupReadSQLForTest() string         { return rollupReadSQL }
func RollupReadBySourceSQLForTest() string { return rollupReadBySourceSQL }
func RollupReadPathsSQLForTest() string    { return rollupReadPathsSQL }

// Edge statements of the stats rollup path, by kind, for the planner pins.
func EdgeSQLForTest(kind string, e Edge, accessOnly bool) string {
	switch kind {
	case "total":
		return edgeTotalSQL(e)
	case "source":
		return edgeSourceCountSQL(e)
	case "class":
		return edgeClassCountSQL(e)
	case "hosts":
		return edgeHostsSQL(e, accessOnly)
	case "durations":
		return edgeDurationsSQL(e, accessOnly)
	case "paths":
		return edgePathsSQL(e)
	case "class series":
		return edgeClassSeriesSQL(e)
	case "total series":
		return edgeTotalSeriesSQL(e, accessOnly)
	}
	return ""
}
