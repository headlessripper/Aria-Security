from Services.SentinelUSBGuard import is_external_storage, diff_drives, is_allowlisted

def test_usb_flash_is_external():
    assert is_external_storage({"letter": "E:", "drive_type": 2, "bus_type": 7}) is True

def test_external_ssd_reported_fixed_is_external():
    # external SSD on USB: Windows says DRIVE_FIXED(3) but bus is USB(7)
    assert is_external_storage({"letter": "F:", "drive_type": 3, "bus_type": 7}) is True

def test_internal_disk_not_external():
    # internal SATA SSD: FIXED + SATA bus (11), removable_media False
    assert is_external_storage({"letter": "C:", "drive_type": 3, "bus_type": 11, "removable_media": False}) is False

def test_network_drive_not_external():
    assert is_external_storage({"letter": "Z:", "drive_type": 4, "bus_type": 0}) is False

def test_removable_media_flag_is_external():
    assert is_external_storage({"letter": "G:", "drive_type": 3, "bus_type": 0, "removable_media": True}) is True

def test_diff_drives():
    new, removed = diff_drives({"C:", "D:"}, {"C:", "D:", "E:"})
    assert new == {"E:"} and removed == set()
    new, removed = diff_drives({"C:", "E:"}, {"C:"})
    assert new == set() and removed == {"E:"}

def test_allowlist():
    al = {"VOL-1234", "MyUSB"}
    assert is_allowlisted({"serial": "VOL-1234"}, al) is True
    assert is_allowlisted({"label": "MyUSB"}, al) is True
    assert is_allowlisted({"serial": "OTHER", "label": "x"}, al) is False
