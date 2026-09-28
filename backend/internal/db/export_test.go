package db

// Statement accessors for the planner-pin tests in db_test (the
// package's own tests would see the constants; the external test
// package keeps the real-migration schema through dbtest).
func RollupReadSQLForTest() string         { return rollupReadSQL }
func RollupReadBySourceSQLForTest() string { return rollupReadBySourceSQL }
func RollupReadPathsSQLForTest() string    { return rollupReadPathsSQL }
