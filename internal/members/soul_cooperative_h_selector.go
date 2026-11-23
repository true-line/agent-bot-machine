package members

// SoulCooperativeHSelectorV3 contains only A-derived lookup fields for one
// installed cooperative run. It grants no start and accepts no HQ plan bytes.
type SoulCooperativeHSelectorV3 struct {
	HOwnerPlanDigest      string
	HQInstallationID      string
	CooperativePlanID     string
	CooperativePlanDigest string
	Owner                 string
}
