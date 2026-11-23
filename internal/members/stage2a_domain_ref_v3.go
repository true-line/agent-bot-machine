package members

// The compact H/R reference is a wire and receipt type on every build OS.
// Only Darwin's A-owned no-follow observer can construct a verified instance.
type stage2aDomainNodeRefV3 struct {
	Path        string `json:"path"`
	Device      string `json:"device"`
	Inode       string `json:"inode"`
	Generation  string `json:"generation"`
	BirthtimeNS string `json:"birthtime_ns"`
	OwnerUID    uint32 `json:"owner_uid"`
	OwnerGID    uint32 `json:"owner_gid"`
	Mode        string `json:"mode"`
}

type stage2aDomainSidecarRefV3 struct {
	stage2aDomainNodeRefV3
	SizeBytes uint64 `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

type stage2aDomainInventoryRefV3 struct {
	Contract                      string                    `json:"contract"`
	Kind                          string                    `json:"kind"`
	SchemaVersion                 int                       `json:"schema_version"`
	Domain                        string                    `json:"domain"`
	InstallationID                string                    `json:"installation_id"`
	OwnerPlanDigest               string                    `json:"owner_plan_digest"`
	ReviewedSourceInventoryDigest string                    `json:"reviewed_source_inventory_digest"`
	MachineUID                    uint32                    `json:"machine_uid"`
	ReaderUID                     uint32                    `json:"reader_uid"`
	ReaderGID                     uint32                    `json:"reader_gid"`
	Snapshot                      stage2aDomainNodeRefV3    `json:"snapshot"`
	Sidecar                       stage2aDomainSidecarRefV3 `json:"sidecar"`
	FileCount                     int                       `json:"file_count"`
	DirectoryCount                int                       `json:"directory_count"`
	TotalBytes                    uint64                    `json:"total_bytes"`
	InventoryDigest               string                    `json:"inventory_digest"`
}
