# Engine_Unit_SG.py

import ctypes, ctypes.wintypes

####################################################################################################

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.wintypes.DWORD),
        ("Data2", ctypes.wintypes.WORD),
        ("Data3", ctypes.wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8)]

# Catalog verification (CryptCATAdmin* + WinVerifyTrust with WTD_CHOICE_CATALOG).
# Most modern Windows system binaries are catalog-signed (their Authenticode
# signature lives in a system .cat, not embedded in the PE), so the embedded
# WTD_CHOICE_FILE path reads them as untrusted. These structs drive the catalog path.

_MAX_PATH = 260

class CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.wintypes.DWORD),
        ("wszCatalogFile", ctypes.wintypes.WCHAR * _MAX_PATH)]

class WINTRUST_CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.wintypes.DWORD),
        ("dwCatalogVersion", ctypes.wintypes.DWORD),
        ("pcwszCatalogFilePath", ctypes.wintypes.LPCWSTR),
        ("pcwszMemberTag", ctypes.wintypes.LPCWSTR),
        ("pcwszMemberFilePath", ctypes.wintypes.LPCWSTR),
        ("hMemberFile", ctypes.wintypes.HANDLE),
        ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCalculatedFileHash", ctypes.wintypes.DWORD),
        ("pcCatalogContext", ctypes.wintypes.LPVOID),
        ("hCatAdmin", ctypes.wintypes.HANDLE)]

# DRIVER_ACTION_VERIFY subsystem GUID {F750E6C3-38EE-11D1-85E5-00C04FC295EE}
_DRIVER_ACTION_VERIFY = GUID(0xF750E6C3, 0x38EE, 0x11D1,
    (0x85, 0xE5, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.wintypes.DWORD),
        ("pcwszFilePath", ctypes.wintypes.LPCWSTR),
        ("hFile", ctypes.wintypes.HANDLE),
        ("pgKnownSubject", ctypes.wintypes.LPVOID)]

class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.wintypes.LPVOID),
        ("pSIPClientData", ctypes.wintypes.LPVOID),
        ("dwUIChoice", ctypes.wintypes.DWORD),
        ("fdwRevocationChecks", ctypes.wintypes.DWORD),
        ("dwUnionChoice", ctypes.wintypes.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", ctypes.wintypes.DWORD),
        ("hWVTStateData", ctypes.wintypes.HANDLE),
        ("pwszURLReference", ctypes.wintypes.LPCWSTR),
        ("dwProvFlags", ctypes.wintypes.DWORD),
        ("dwUIContext", ctypes.wintypes.DWORD),
        ("pSignatureSettings", ctypes.wintypes.LPVOID)]

class sign_scanner:
    def __init__(self):
        self.verify = GUID(0x00AAC56B, 0xCD44, 0x11D0, (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

    def init_windll(self, path):
        for name in path:
            try:
                setattr(self, name.lower(), ctypes.WinDLL(name, use_last_error=True))
            except Exception:
                pass

        try:
            self.WinVerifyTrust = self.wintrust.WinVerifyTrust
            self.WinVerifyTrust.restype = ctypes.wintypes.LONG
            self.WinVerifyTrust.argtypes = [ctypes.wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
        except Exception:
            pass

    def sign_verify(self, file_path):
        try:
            fi = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), file_path, None, None)
            data = WINTRUST_DATA(ctypes.sizeof(WINTRUST_DATA), None, None, 2, 0, 1,
                ctypes.pointer(fi), 1, None, None, 0, 0, None)
            s = self.WinVerifyTrust(None, ctypes.byref(self.verify), ctypes.byref(data))
            data.dwStateAction = 2
            self.WinVerifyTrust(None, ctypes.byref(self.verify), ctypes.byref(data))
            return s == 0
        except Exception:
            return False

    def catalog_verify(self, file_path):
        """Verify a catalog-signed (not embedded) PE via CryptCATAdmin* + WinVerifyTrust
        with WTD_CHOICE_CATALOG. Returns True iff a system catalog vouches for the file's
        hash and the catalog signature verifies. Fully defensive: any API/ctypes failure
        (missing DLL export, no catalog, verify != 0) returns False, never raises."""
        wt = getattr(self, "wintrust", None)
        if wt is None:
            return False

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateFileW.restype = ctypes.wintypes.HANDLE
        k32.CreateFileW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD,
                                    ctypes.wintypes.DWORD, ctypes.wintypes.LPVOID,
                                    ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
                                    ctypes.wintypes.HANDLE]
        k32.CloseHandle.restype = ctypes.wintypes.BOOL
        k32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        OPEN_EXISTING = 3
        INVALID_HANDLE = ctypes.wintypes.HANDLE(-1).value

        h_cat_admin = ctypes.wintypes.HANDLE()
        h_file = None
        h_cat_info = None

        # ---- acquire catalog-admin context (SHA256 preferred, SHA1 fallback) ----
        use_sha256 = True
        acquired = False
        try:
            acq2 = wt.CryptCATAdminAcquireContext2
            acq2.restype = ctypes.wintypes.BOOL
            acq2.argtypes = [ctypes.POINTER(ctypes.wintypes.HANDLE), ctypes.POINTER(GUID),
                             ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPVOID, ctypes.wintypes.DWORD]
            acquired = bool(acq2(ctypes.byref(h_cat_admin),
                                 ctypes.byref(_DRIVER_ACTION_VERIFY), "SHA256", None, 0))
        except Exception:
            acquired = False

        if not acquired:
            use_sha256 = False
            try:
                acq = wt.CryptCATAdminAcquireContext
                acq.restype = ctypes.wintypes.BOOL
                acq.argtypes = [ctypes.POINTER(ctypes.wintypes.HANDLE),
                                ctypes.POINTER(GUID), ctypes.wintypes.DWORD]
                acquired = bool(acq(ctypes.byref(h_cat_admin),
                                    ctypes.byref(_DRIVER_ACTION_VERIFY), 0))
            except Exception:
                acquired = False

        if not acquired or not h_cat_admin.value:
            return False

        try:
            # ---- open the target file ----
            h_file = k32.CreateFileW(ctypes.wintypes.LPCWSTR(file_path),
                                     GENERIC_READ, FILE_SHARE_READ, None,
                                     OPEN_EXISTING, 0, None)
            if not h_file or h_file == INVALID_HANDLE:
                return False

            # ---- compute the file hash (size, then fill) ----
            cb_hash = ctypes.wintypes.DWORD(0)
            if use_sha256:
                calc = wt.CryptCATAdminCalcHashFromFileHandle2
                calc.restype = ctypes.wintypes.BOOL
                calc.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.HANDLE,
                                 ctypes.POINTER(ctypes.wintypes.DWORD),
                                 ctypes.POINTER(ctypes.c_ubyte), ctypes.wintypes.DWORD]
                calc(h_cat_admin, h_file, ctypes.byref(cb_hash), None, 0)
                if not cb_hash.value:
                    return False
                pb_hash = (ctypes.c_ubyte * cb_hash.value)()
                if not calc(h_cat_admin, h_file, ctypes.byref(cb_hash), pb_hash, 0):
                    return False
            else:
                calc = wt.CryptCATAdminCalcHashFromFileHandle
                calc.restype = ctypes.wintypes.BOOL
                calc.argtypes = [ctypes.wintypes.HANDLE,
                                 ctypes.POINTER(ctypes.wintypes.DWORD),
                                 ctypes.POINTER(ctypes.c_ubyte), ctypes.wintypes.DWORD]
                calc(h_file, ctypes.byref(cb_hash), None, 0)
                if not cb_hash.value:
                    return False
                pb_hash = (ctypes.c_ubyte * cb_hash.value)()
                if not calc(h_file, ctypes.byref(cb_hash), pb_hash, 0):
                    return False

            # ---- find a catalog that contains this hash ----
            enum = wt.CryptCATAdminEnumCatalogFromHash
            enum.restype = ctypes.wintypes.HANDLE
            enum.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.c_ubyte),
                             ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
                             ctypes.POINTER(ctypes.wintypes.HANDLE)]
            h_cat_info = enum(h_cat_admin, pb_hash, cb_hash, 0, None)
            if not h_cat_info:
                return False  # no catalog vouches for this file

            # ---- catalog file path for this context ----
            cat_info = CATALOG_INFO()
            cat_info.cbStruct = ctypes.sizeof(CATALOG_INFO)
            info_from_ctx = wt.CryptCATCatalogInfoFromContext
            info_from_ctx.restype = ctypes.wintypes.BOOL
            info_from_ctx.argtypes = [ctypes.wintypes.HANDLE,
                                      ctypes.POINTER(CATALOG_INFO), ctypes.wintypes.DWORD]
            if not info_from_ctx(h_cat_info, ctypes.byref(cat_info), 0):
                return False

            # ---- member tag = uppercase hex of the file hash ----
            member_tag = "".join("{:02X}".format(b) for b in pb_hash)

            wci = WINTRUST_CATALOG_INFO()
            wci.cbStruct = ctypes.sizeof(WINTRUST_CATALOG_INFO)
            wci.dwCatalogVersion = 0
            wci.pcwszCatalogFilePath = cat_info.wszCatalogFile
            wci.pcwszMemberTag = member_tag
            wci.pcwszMemberFilePath = file_path
            wci.hMemberFile = h_file
            wci.pbCalculatedFileHash = ctypes.cast(pb_hash, ctypes.POINTER(ctypes.c_ubyte))
            wci.cbCalculatedFileHash = cb_hash
            wci.pcCatalogContext = None
            wci.hCatAdmin = h_cat_admin

            # WINTRUST_DATA with dwUnionChoice = WTD_CHOICE_CATALOG (2); the pFile
            # union slot is a pointer at the same offset as pCatalog.
            data = WINTRUST_DATA(ctypes.sizeof(WINTRUST_DATA), None, None,
                                 2,  # WTD_UI_NONE
                                 0,  # WTD_REVOKE_NONE
                                 2,  # WTD_CHOICE_CATALOG
                                 ctypes.cast(ctypes.pointer(wci),
                                             ctypes.POINTER(WINTRUST_FILE_INFO)),
                                 1,  # WTD_STATEACTION_VERIFY
                                 None, None, 0, 0, None)
            s = self.WinVerifyTrust(None, ctypes.byref(self.verify), ctypes.byref(data))
            data.dwStateAction = 2  # WTD_STATEACTION_CLOSE
            try:
                self.WinVerifyTrust(None, ctypes.byref(self.verify), ctypes.byref(data))
            except Exception:
                pass
            return s == 0
        except Exception:
            return False
        finally:
            try:
                if h_cat_info:
                    rel = wt.CryptCATAdminReleaseCatalogContext
                    rel.restype = ctypes.wintypes.BOOL
                    rel.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.HANDLE,
                                    ctypes.wintypes.DWORD]
                    rel(h_cat_admin, h_cat_info, 0)
            except Exception:
                pass
            try:
                relc = wt.CryptCATAdminReleaseContext
                relc.restype = ctypes.wintypes.BOOL
                relc.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD]
                relc(h_cat_admin, 0)
            except Exception:
                pass
            try:
                if h_file and h_file != INVALID_HANDLE:
                    k32.CloseHandle(h_file)
            except Exception:
                pass