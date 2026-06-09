package updater

import (
	"io"
	"log/slog"
	"testing"
)

func TestCheckForUpdateSkipsDevelopmentBuild(t *testing.T) {
	oldVersion := Version
	Version = developmentVersion
	t.Cleanup(func() { Version = oldVersion })

	release, hasUpdate, err := CheckForUpdate()
	if err != nil {
		t.Fatal(err)
	}
	if release != nil || hasUpdate {
		t.Fatalf("development build should not check for updates, got release=%#v hasUpdate=%v", release, hasUpdate)
	}
}

func TestCheckForUpdateCanBeDisabledByEnv(t *testing.T) {
	oldVersion := Version
	Version = "v1.0.0"
	t.Cleanup(func() { Version = oldVersion })
	t.Setenv(disableUpdateEnv, "true")

	release, hasUpdate, err := CheckForUpdate()
	if err != nil {
		t.Fatal(err)
	}
	if release != nil || hasUpdate {
		t.Fatalf("disabled update should not check for updates, got release=%#v hasUpdate=%v", release, hasUpdate)
	}
}

func TestUpdateCheckerStartReturnsWhenDevelopmentBuildIsSkipped(t *testing.T) {
	oldVersion := Version
	Version = developmentVersion
	t.Cleanup(func() { Version = oldVersion })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	checker := NewUpdateChecker(ComponentServer, logger)
	checker.Start()
	checker.Stop()
}
