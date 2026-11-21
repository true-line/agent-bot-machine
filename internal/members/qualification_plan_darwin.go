package members

func verifyQualificationExecutable(path, digest string) error {
	return verifyHarnessExecutableLimit(path, digest, 2<<30)
}
