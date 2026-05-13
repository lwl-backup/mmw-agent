package limiter

type UserInfo struct {
	UID         int
	Email       string
	SpeedLimit  uint64 // Bytes/s, 0 = unlimited
	DeviceLimit int    // 0 = unlimited
}
