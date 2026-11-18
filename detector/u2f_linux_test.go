package detector

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rjeczalik/notify"
)

// The U2F watcher retries a key it could not open when the key's permissions
// change; logind grants access through an ACL, which inotify reports as an
// attribute change of the file inside the watched directory
func TestDirectoryWatchReportsPermissionChanges(t *testing.T) {
	dir := t.TempDir()
	device := filepath.Join(dir, "hidraw9")
	if err := os.WriteFile(device, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	events := make(chan notify.EventInfo, 10)
	if err := notify.Watch(dir, events, notify.Create, notify.InAttrib); err != nil {
		t.Fatal(err)
	}
	defer notify.Stop(events)

	if err := os.Chmod(device, 0o660); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case event := <-events:
			if event.Event() == notify.InAttrib && filepath.Base(event.Path()) == "hidraw9" {
				return
			}
		case <-deadline:
			t.Fatal("no attribute change event for the device")
		}
	}
}

func TestIsFidoU2FDeviceReportsPermissionErrors(t *testing.T) {
	devices, _ := filepath.Glob("/dev/hidraw*")
	for _, device := range devices {
		file, err := os.Open(device)
		if err == nil {
			file.Close()
			continue
		}
		if !errors.Is(err, fs.ErrPermission) {
			continue
		}
		isFido, err := isFidoU2FDevice(device)
		if isFido || !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("isFidoU2FDevice(%s) = %t, %v, want a permission error", device, isFido, err)
		}
		return
	}
	t.Skip("no hidraw device this user may not open")
}

func TestIsFidoU2FDeviceIgnoresOtherPaths(t *testing.T) {
	if isFido, err := isFidoU2FDevice("/dev/null"); isFido || err != nil {
		t.Fatalf("isFidoU2FDevice(/dev/null) = %t, %v, want false, nil", isFido, err)
	}
}
