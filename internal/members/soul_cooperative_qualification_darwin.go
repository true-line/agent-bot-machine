package members

// Join the independently loaded and remeasured Q plan to the applied
// cooperative R plan. The paired caller supplies identifiers; A obtains
// the two plan records from their respective installed custody paths.
func cooperativeQualificationHarnessV3(install stage2aQualificationQInstall, request QualificationRequest,
	p SoulCooperativeLaunchPolicy, owner, planDigest, inventoryDigest string) (string, error) {
	candidate := request.Candidate
	adapter := p.AdapterRelease
	review := install.Review
	if candidate == nil || adapter == nil || p.LaunchInputs == nil || p.QualificationProvider == nil ||
		review.Owner != owner || review.HostID != p.HostID ||
		review.InstallationID != p.Runner.InstallationID || review.InstalledPlanDigest != planDigest ||
		install.AdminUID != p.MachineUID || install.AdminGID != p.MachineGID ||
		install.HQUID != p.HQUID || install.RunnerGID != p.Runner.GID ||
		request.Target.Account != p.Runner.Account || request.Target.UID != p.Runner.UID ||
		"sha256:"+candidate.RuntimeInventorySHA != inventoryDigest || candidate.ComponentID != adapter.ComponentID ||
		"sha256:"+candidate.Manifest.SHA256 != adapter.ReleaseManifestSHA256 ||
		"sha256:"+request.Adapter.PackageSHA != adapter.PackageSHA256 ||
		request.Adapter.Launch.Executable != adapter.ExecutablePath ||
		"sha256:"+request.Adapter.Launch.ExecutableSHA != adapter.ExecutableSHA256 {
		return "", errSoulCooperativeAuthority
	}
	_, providerConfigSHA, err := stage2aProviderConfig(*p.QualificationProvider)
	harnessSHA := "sha256:" + request.Adapter.Harness.BinarySHA
	if err != nil || providerConfigSHA != review.Provider.SHA256 ||
		"sha256:"+providerConfigSHA != p.LaunchInputs.EffectiveConfig["qualification_provider_config_sha256"] ||
		harnessSHA != p.LaunchInputs.ComponentDigests["harness"] {
		return "", errSoulCooperativeAuthority
	}
	return harnessSHA, nil
}
