// SafeReturn S0 spike — VSS requester helper.
//
// WHY THIS FILE EXISTS (S0 finding, 2026-10-20):
// The Rust `windows` crate (0.61.3) does not expose the VSS *requester*
// interface IVssBackupComponents at all — its Win32::Storage::Vss module
// ships writer/provider/management interfaces only, and CreateVssBackupComponents
// is likewise absent. Hand-defining that COM interface in Rust would mean
// transcribing a ~50-method vtable whose order we cannot verify without the
// SDK header — an unacceptable silent-failure risk in backup software.
// So the requester lives here, compiled against the real vsbackup.h +
// VssApi.lib, behind a narrow C ABI that the Rust state machine drives.
//
// STATUS: written to Microsoft Learn's documented signatures/sequence.
// Compile verification requires a Windows SDK machine (or windows-latest CI
// runner) — NOT yet compile-verified as of 2026-10-20. First CI job for the
// future repo: build this file. Do not ship product code from it until then.
//
// Sequence (Learn: Requesters / Overview of Pre-Backup Tasks):
//   CreateVssBackupComponents -> InitializeForBackup
//   -> SetBackupState(TRUE, TRUE, VSS_BT_FULL, FALSE)
//   -> GatherWriterMetadata (+ IVssAsync::Wait)
//   -> StartSnapshotSet -> AddToSnapshotSet(volume, GUID_NULL)
//   -> PrepareForBackup (+Wait) -> DoSnapshotSet (+Wait)
//   -> GetSnapshotProperties (snapshot device object for reading locked files)
//   -> BackupComplete (+Wait) -> DeleteSnapshots -> Release
//
// Must run elevated: Create/Initialize return E_ACCESSDENIED without
// administrator + backup privilege.

#include <windows.h>
#include <objbase.h>
#include <vss.h>
#include <vswriter.h>  // Required: Learn's vsbackup.h requirements list
                       // "include VsBackup.h, Vss.h, VsWriter.h". Without
                       // it, CI run #3 failed inside vsbackup.h itself —
                       // VSS_COMPONENT_TYPE, IVssWMFiledesc and friends
                       // are defined here, not in vss.h.
#include <vsbackup.h>
#include <cstring>

struct SRVssSession {
    IVssBackupComponents* backup = nullptr;
    VSS_ID snapshotSetId = GUID_NULL;
    VSS_ID snapshotId = GUID_NULL;
    bool snapshotCreated = false;
    bool initialized = false;
};

static HRESULT WaitForAsync(IVssAsync* async) {
    if (!async) return E_POINTER;
    HRESULT hr = async->Wait();
    if (SUCCEEDED(hr)) {
        HRESULT hrResult = S_OK;
        hr = async->QueryStatus(&hrResult, nullptr);
        if (SUCCEEDED(hr)) hr = hrResult;
    }
    async->Release();
    return hr;
}

extern "C" {

// Returns nullptr on failure; call sr_vss_last_error() pattern is v2 work —
// for the spike, each step returns its HRESULT directly.
__declspec(dllexport) SRVssSession* sr_vss_create(long* out_hr) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        if (out_hr) *out_hr = hr;
        return nullptr;
    }
    auto* s = new SRVssSession();
    hr = CreateVssBackupComponents(&s->backup);
    if (FAILED(hr)) {
        if (out_hr) *out_hr = hr;
        delete s;
        return nullptr;
    }
    if (out_hr) *out_hr = S_OK;
    return s;
}

__declspec(dllexport) long sr_vss_initialize(SRVssSession* s) {
    if (!s || !s->backup) return E_POINTER;
    HRESULT hr = s->backup->InitializeForBackup(nullptr);
    if (FAILED(hr)) return hr;
    // Component mode, bootable system state, FULL, no partial-file support.
    hr = s->backup->SetBackupState(TRUE, TRUE, VSS_BT_FULL, FALSE);
    if (SUCCEEDED(hr)) s->initialized = true;
    return hr;
}

__declspec(dllexport) long sr_vss_gather_metadata(SRVssSession* s) {
    if (!s || !s->backup || !s->initialized) return VSS_E_BAD_STATE;
    IVssAsync* async = nullptr;
    HRESULT hr = s->backup->GatherWriterMetadata(&async);
    if (FAILED(hr)) return hr;
    hr = WaitForAsync(async);
    // TODO S0.5: enumerate GatherWriterStatus/GetWriterStatus and surface
    // per-writer failures by name to Rust (needed for the pre-flight check
    // in the First Backup flow). Spike stops at "gather completed".
    return hr;
}

__declspec(dllexport) long sr_vss_snapshot_volume(SRVssSession* s,
                                                  const wchar_t* volume,
                                                  wchar_t* device_out,
                                                  size_t device_out_cch) {
    if (!s || !s->backup || !s->initialized) return VSS_E_BAD_STATE;
    HRESULT hr = s->backup->StartSnapshotSet(&s->snapshotSetId);
    if (FAILED(hr)) return hr;
    hr = s->backup->AddToSnapshotSet(const_cast<VSS_PWSZ>(volume), GUID_NULL, &s->snapshotId);
    if (FAILED(hr)) return hr;

    IVssAsync* async = nullptr;
    hr = s->backup->PrepareForBackup(&async);
    if (FAILED(hr)) return hr;
    hr = WaitForAsync(async);
    if (FAILED(hr)) return hr;

    async = nullptr;
    hr = s->backup->DoSnapshotSet(&async);
    if (FAILED(hr)) return hr;
    hr = WaitForAsync(async);
    if (FAILED(hr)) return hr;
    s->snapshotCreated = true;

    VSS_SNAPSHOT_PROP prop{};
    hr = s->backup->GetSnapshotProperties(s->snapshotId, &prop);
    if (FAILED(hr)) return hr;
    if (device_out && device_out_cch > 0) {
        wcsncpy_s(device_out, device_out_cch, prop.m_pwszSnapshotDeviceObject, _TRUNCATE);
    }
    VssFreeSnapshotProperties(&prop);
    return S_OK;
}

__declspec(dllexport) long sr_vss_destroy(SRVssSession* s, bool complete) {
    if (!s) return S_OK;
    HRESULT hr = S_OK;
    if (s->backup) {
        if (s->snapshotCreated && complete) {
            IVssAsync* async = nullptr;
            HRESULT hrComplete = s->backup->BackupComplete(&async);
            if (SUCCEEDED(hrComplete)) hrComplete = WaitForAsync(async);
            if (FAILED(hrComplete)) hr = hrComplete;
        } else if (s->snapshotCreated) {
            s->backup->AbortBackup();
        }
        if (s->snapshotCreated) {
            LONG deleted = 0;
            VSS_ID nonDeleted = GUID_NULL;
            s->backup->DeleteSnapshots(s->snapshotId, VSS_OBJECT_SNAPSHOT,
                                       FALSE, &deleted, &nonDeleted);
        }
        s->backup->Release();
    }
    delete s;
    CoUninitialize();
    return hr;
}

} // extern "C"
