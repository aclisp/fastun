package subnet

func NewMockManager(registry *MockSubnetRegistry) Manager {
	return newLocalManager(registry)
}
