//! Handle-bound, read-only collection of official Wintun artifact evidence.
//!
//! The collector hashes an already-staged archive, license, and DLL. It parses
//! the DLL's PE machine and asks Windows to validate Authenticode against the
//! same open file handle. It never loads the DLL, creates an adapter, installs
//! a route, or reads or changes DNS, proxy, PAC, or VPN state.

use super::{
    admit_windows_packet_adapter_artifact, WindowsPacketAdapterArchitecture,
    WindowsPacketAdapterArtifactAdmission, WindowsPacketAdapterArtifactEvidence,
    WindowsPacketAdapterErrorCode, WindowsPacketAdapterSignatureStatus, WINTUN_AMD64_DLL_PATH,
    WINTUN_ARM64_DLL_PATH, WINTUN_VERSION,
};
use crate::service_ownership::windows::{
    final_path_matches, open_readonly, raw_handle, validate_regular_file, NativeEvidenceError,
};
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{
    CERT_E_CHAINING, CERT_E_EXPIRED, CERT_E_REVOKED, CERT_E_UNTRUSTEDROOT,
    CRYPT_E_SECURITY_SETTINGS, GENERIC_READ, INVALID_HANDLE_VALUE, TRUST_E_BAD_DIGEST,
    TRUST_E_EXPLICIT_DISTRUST, TRUST_E_NOSIGNATURE,
};
use windows_sys::Win32::Security::Cryptography::{
    szOID_ORGANIZATION_NAME, CertGetCertificateContextProperty, CertGetNameStringW, CERT_CONTEXT,
    CERT_NAME_ATTR_TYPE, CERT_SHA256_HASH_PROP_ID,
};
use windows_sys::Win32::Security::WinTrust::{
    WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    WinVerifyTrust, CRYPT_PROVIDER_DATA, CRYPT_PROVIDER_SGNR, SGNR_TYPE_TIMESTAMP,
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4, WTD_REVOKE_NONE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UICONTEXT_EXECUTE, WTD_UI_NONE,
};
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

const MAX_WINTUN_ARCHIVE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_WINTUN_LICENSE_BYTES: u64 = 128 * 1024;
const MAX_WINTUN_DLL_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CERTIFICATE_NAME_UTF16_UNITS: u32 = 4096;
const MAX_COUNTERSIGNERS: u32 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsPacketAdapterArtifactKind {
    Archive,
    License,
    Dll,
}

impl WindowsPacketAdapterArtifactKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::License => "license",
            Self::Dll => "dll",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsPacketAdapterCollectorError {
    MissingArtifact(WindowsPacketAdapterArtifactKind),
    InaccessibleArtifact(WindowsPacketAdapterArtifactKind),
    InvalidArtifact(WindowsPacketAdapterArtifactKind),
    InvalidPe,
    AuthenticodeEvidenceUnavailable,
    AuthenticodeStateCloseFailed(i32),
    CertificateNameUnavailable,
    CertificateHashUnavailable,
}

impl WindowsPacketAdapterCollectorError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingArtifact(_) => "artifact_missing",
            Self::InaccessibleArtifact(_) => "artifact_inaccessible",
            Self::InvalidArtifact(_) => "artifact_invalid",
            Self::InvalidPe => "pe_invalid",
            Self::AuthenticodeEvidenceUnavailable => "authenticode_evidence_unavailable",
            Self::AuthenticodeStateCloseFailed(_) => "authenticode_state_close_failed",
            Self::CertificateNameUnavailable => "certificate_name_unavailable",
            Self::CertificateHashUnavailable => "certificate_hash_unavailable",
        }
    }
}

#[derive(Debug)]
pub struct WindowsCollectedPacketAdapterArtifact {
    architecture: WindowsPacketAdapterArchitecture,
    evidence: WindowsPacketAdapterArtifactEvidence,
    dll_path: PathBuf,
    dll_file: File,
}

impl WindowsCollectedPacketAdapterArtifact {
    pub const fn architecture(&self) -> WindowsPacketAdapterArchitecture {
        self.architecture
    }

    pub fn evidence(&self) -> &WindowsPacketAdapterArtifactEvidence {
        &self.evidence
    }

    pub fn admit(
        self,
    ) -> Result<WindowsCollectedPacketAdapterAdmission, WindowsPacketAdapterErrorCode> {
        let admission =
            admit_windows_packet_adapter_artifact(self.architecture.as_str(), &self.evidence)?;
        Ok(WindowsCollectedPacketAdapterAdmission {
            admission,
            evidence: self.evidence,
            dll_path: self.dll_path,
            dll_file: self.dll_file,
        })
    }
}

#[derive(Debug)]
pub struct WindowsCollectedPacketAdapterAdmission {
    admission: WindowsPacketAdapterArtifactAdmission,
    evidence: WindowsPacketAdapterArtifactEvidence,
    dll_path: PathBuf,
    dll_file: File,
}

impl WindowsCollectedPacketAdapterAdmission {
    pub fn artifact_admission(&self) -> &WindowsPacketAdapterArtifactAdmission {
        &self.admission
    }

    pub fn evidence(&self) -> &WindowsPacketAdapterArtifactEvidence {
        &self.evidence
    }

    pub fn dll_path(&self) -> &Path {
        &self.dll_path
    }

    pub fn retained_dll_length(&self) -> Result<u64, WindowsPacketAdapterCollectorError> {
        validate_regular_file(&self.dll_file, MAX_WINTUN_DLL_BYTES)
            .map_err(|error| map_file_error(WindowsPacketAdapterArtifactKind::Dll, error))
    }
}

pub fn collect_windows_packet_adapter_artifact(
    architecture: WindowsPacketAdapterArchitecture,
    archive_path: &Path,
    license_path: &Path,
    dll_path: &Path,
) -> Result<WindowsCollectedPacketAdapterArtifact, WindowsPacketAdapterCollectorError> {
    let (archive_length, archive_sha256) = hash_artifact(
        WindowsPacketAdapterArtifactKind::Archive,
        archive_path,
        MAX_WINTUN_ARCHIVE_BYTES,
    )?;
    let (_, license_sha256) = hash_artifact(
        WindowsPacketAdapterArtifactKind::License,
        license_path,
        MAX_WINTUN_LICENSE_BYTES,
    )?;

    let mut dll = open_artifact(
        WindowsPacketAdapterArtifactKind::Dll,
        dll_path,
        MAX_WINTUN_DLL_BYTES,
    )?;
    let dll_sha256 = hash_opened_file(
        WindowsPacketAdapterArtifactKind::Dll,
        &mut dll.file,
        dll.length,
    )?;
    let pe_machine = read_pe_machine(&mut dll.file, dll.length)?;
    let signature = verify_authenticode(&dll.file, &dll.path)?;
    let dll_logical_path = match architecture {
        WindowsPacketAdapterArchitecture::Amd64 => WINTUN_AMD64_DLL_PATH,
        WindowsPacketAdapterArchitecture::Arm64 => WINTUN_ARM64_DLL_PATH,
    };

    Ok(WindowsCollectedPacketAdapterArtifact {
        architecture,
        evidence: WindowsPacketAdapterArtifactEvidence {
            version: WINTUN_VERSION.to_owned(),
            archive_sha256,
            archive_length,
            license_sha256,
            dll_path: dll_logical_path.to_owned(),
            dll_sha256,
            dll_length: dll.length,
            pe_machine,
            signature_status: signature.status,
            publisher: signature.publisher,
            signer_sha256: signature.signer_sha256,
            timestamped: signature.timestamped,
        },
        dll_path: dll.path,
        dll_file: dll.file,
    })
}

struct OpenedArtifact {
    file: File,
    path: PathBuf,
    length: u64,
}

fn open_artifact(
    kind: WindowsPacketAdapterArtifactKind,
    path: &Path,
    maximum_size: u64,
) -> Result<OpenedArtifact, WindowsPacketAdapterCollectorError> {
    let file = open_readonly(path, GENERIC_READ, FILE_SHARE_READ)
        .map_err(|error| map_file_error(kind, error))?;
    let length =
        validate_regular_file(&file, maximum_size).map_err(|error| map_file_error(kind, error))?;
    if !final_path_matches(&file, path).map_err(|error| map_file_error(kind, error))? {
        return Err(WindowsPacketAdapterCollectorError::InvalidArtifact(kind));
    }
    let path = path
        .canonicalize()
        .map_err(|_| WindowsPacketAdapterCollectorError::InaccessibleArtifact(kind))?;
    Ok(OpenedArtifact { file, path, length })
}

fn hash_artifact(
    kind: WindowsPacketAdapterArtifactKind,
    path: &Path,
    maximum_size: u64,
) -> Result<(u64, String), WindowsPacketAdapterCollectorError> {
    let mut artifact = open_artifact(kind, path, maximum_size)?;
    let digest = hash_opened_file(kind, &mut artifact.file, artifact.length)?;
    Ok((artifact.length, digest))
}

fn hash_opened_file(
    kind: WindowsPacketAdapterArtifactKind,
    file: &mut File,
    expected_length: u64,
) -> Result<String, WindowsPacketAdapterCollectorError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| WindowsPacketAdapterCollectorError::InaccessibleArtifact(kind))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| WindowsPacketAdapterCollectorError::InaccessibleArtifact(kind))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(WindowsPacketAdapterCollectorError::InvalidArtifact(kind))?;
        if total > expected_length {
            return Err(WindowsPacketAdapterCollectorError::InvalidArtifact(kind));
        }
        hasher.update(&buffer[..read]);
    }
    if total != expected_length {
        return Err(WindowsPacketAdapterCollectorError::InvalidArtifact(kind));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn read_pe_machine(
    file: &mut File,
    file_length: u64,
) -> Result<u16, WindowsPacketAdapterCollectorError> {
    let mut dos_header = [0u8; 64];
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.read_exact(&mut dos_header))
        .map_err(|_| WindowsPacketAdapterCollectorError::InvalidPe)?;
    if &dos_header[..2] != b"MZ" {
        return Err(WindowsPacketAdapterCollectorError::InvalidPe);
    }
    let pe_offset = u32::from_le_bytes(
        dos_header[0x3c..0x40]
            .try_into()
            .map_err(|_| WindowsPacketAdapterCollectorError::InvalidPe)?,
    ) as u64;
    let pe_header_end = pe_offset
        .checked_add(6)
        .ok_or(WindowsPacketAdapterCollectorError::InvalidPe)?;
    if pe_header_end > file_length {
        return Err(WindowsPacketAdapterCollectorError::InvalidPe);
    }
    let mut pe_header = [0u8; 6];
    file.seek(SeekFrom::Start(pe_offset))
        .and_then(|_| file.read_exact(&mut pe_header))
        .map_err(|_| WindowsPacketAdapterCollectorError::InvalidPe)?;
    if &pe_header[..4] != b"PE\0\0" {
        return Err(WindowsPacketAdapterCollectorError::InvalidPe);
    }
    Ok(u16::from_le_bytes([pe_header[4], pe_header[5]]))
}

struct AuthenticodeEvidence {
    status: WindowsPacketAdapterSignatureStatus,
    publisher: String,
    signer_sha256: String,
    timestamped: bool,
}

fn verify_authenticode(
    file: &File,
    path: &Path,
) -> Result<AuthenticodeEvidence, WindowsPacketAdapterCollectorError> {
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    if wide_path[..wide_path.len().saturating_sub(1)].contains(&0) {
        return Err(WindowsPacketAdapterCollectorError::InvalidArtifact(
            WindowsPacketAdapterArtifactKind::Dll,
        ));
    }
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide_path.as_ptr(),
        hFile: raw_handle(file),
        pgKnownSubject: null_mut(),
    };
    let mut trust_data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: null_mut(),
        pSIPClientData: null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: null_mut(),
        pwszURLReference: null_mut(),
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4,
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        pSignatureSettings: null_mut(),
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let verify_status = unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            (&mut trust_data as *mut WINTRUST_DATA).cast::<c_void>(),
        )
    };

    let evidence = if verify_status == 0 {
        extract_valid_authenticode_evidence(&trust_data)
    } else {
        Ok(AuthenticodeEvidence {
            status: signature_status_from_wintrust(verify_status),
            publisher: String::new(),
            signer_sha256: String::new(),
            timestamped: false,
        })
    };

    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    let close_status = unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            (&mut trust_data as *mut WINTRUST_DATA).cast::<c_void>(),
        )
    };
    if close_status != 0 {
        return Err(WindowsPacketAdapterCollectorError::AuthenticodeStateCloseFailed(close_status));
    }
    evidence
}

fn extract_valid_authenticode_evidence(
    trust_data: &WINTRUST_DATA,
) -> Result<AuthenticodeEvidence, WindowsPacketAdapterCollectorError> {
    if trust_data.hWVTStateData.is_null() {
        return Err(WindowsPacketAdapterCollectorError::AuthenticodeEvidenceUnavailable);
    }
    let provider = unsafe { WTHelperProvDataFromStateData(trust_data.hWVTStateData) };
    if provider.is_null() {
        return Err(WindowsPacketAdapterCollectorError::AuthenticodeEvidenceUnavailable);
    }
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) };
    let certificate = signer_certificate(signer)?;
    let publisher = certificate_organization(certificate)?;
    let signer_sha256 = certificate_sha256(certificate)?;
    let timestamped = has_trusted_timestamp(provider, signer);
    Ok(AuthenticodeEvidence {
        status: WindowsPacketAdapterSignatureStatus::Valid,
        publisher,
        signer_sha256,
        timestamped,
    })
}

fn signer_certificate(
    signer: *mut CRYPT_PROVIDER_SGNR,
) -> Result<*const CERT_CONTEXT, WindowsPacketAdapterCollectorError> {
    if signer.is_null() {
        return Err(WindowsPacketAdapterCollectorError::AuthenticodeEvidenceUnavailable);
    }
    let provider_certificate = unsafe { WTHelperGetProvCertFromChain(signer, 0) };
    if provider_certificate.is_null() {
        return Err(WindowsPacketAdapterCollectorError::AuthenticodeEvidenceUnavailable);
    }
    let certificate = unsafe { (*provider_certificate).pCert };
    if certificate.is_null() {
        return Err(WindowsPacketAdapterCollectorError::AuthenticodeEvidenceUnavailable);
    }
    Ok(certificate)
}

fn certificate_organization(
    certificate: *const CERT_CONTEXT,
) -> Result<String, WindowsPacketAdapterCollectorError> {
    let oid = szOID_ORGANIZATION_NAME.cast::<c_void>();
    let required =
        unsafe { CertGetNameStringW(certificate, CERT_NAME_ATTR_TYPE, 0, oid, null_mut(), 0) };
    if required <= 1 || required > MAX_CERTIFICATE_NAME_UTF16_UNITS {
        return Err(WindowsPacketAdapterCollectorError::CertificateNameUnavailable);
    }
    let mut value = vec![0u16; required as usize];
    let written = unsafe {
        CertGetNameStringW(
            certificate,
            CERT_NAME_ATTR_TYPE,
            0,
            oid,
            value.as_mut_ptr(),
            required,
        )
    };
    if written != required || value.last() != Some(&0) {
        return Err(WindowsPacketAdapterCollectorError::CertificateNameUnavailable);
    }
    value.pop();
    String::from_utf16(&value)
        .map_err(|_| WindowsPacketAdapterCollectorError::CertificateNameUnavailable)
}

fn certificate_sha256(
    certificate: *const CERT_CONTEXT,
) -> Result<String, WindowsPacketAdapterCollectorError> {
    let mut length = 0u32;
    let sized = unsafe {
        CertGetCertificateContextProperty(
            certificate,
            CERT_SHA256_HASH_PROP_ID,
            null_mut(),
            &mut length,
        )
    };
    if sized == 0 || length != 32 {
        return Err(WindowsPacketAdapterCollectorError::CertificateHashUnavailable);
    }
    let mut digest = vec![0u8; length as usize];
    let read = unsafe {
        CertGetCertificateContextProperty(
            certificate,
            CERT_SHA256_HASH_PROP_ID,
            digest.as_mut_ptr().cast::<c_void>(),
            &mut length,
        )
    };
    if read == 0 || length != 32 {
        return Err(WindowsPacketAdapterCollectorError::CertificateHashUnavailable);
    }
    Ok(hex_lower(&digest))
}

fn has_trusted_timestamp(
    provider: *mut CRYPT_PROVIDER_DATA,
    signer: *mut CRYPT_PROVIDER_SGNR,
) -> bool {
    if provider.is_null() || signer.is_null() {
        return false;
    }
    let signer_ref = unsafe { &*signer };
    if signer_ref.csCounterSigners == 0
        || signer_ref.csCounterSigners > MAX_COUNTERSIGNERS
        || signer_ref.pasCounterSigners.is_null()
    {
        return false;
    }
    (0..signer_ref.csCounterSigners).any(|index| {
        let countersigner = unsafe { WTHelperGetProvSignerFromChain(provider, 0, 1, index) };
        if countersigner.is_null() {
            return false;
        }
        let countersigner_ref = unsafe { &*countersigner };
        let timestamp = countersigner_ref.sftVerifyAsOf;
        countersigner_ref.dwSignerType == SGNR_TYPE_TIMESTAMP
            && countersigner_ref.dwError == 0
            && (timestamp.dwLowDateTime != 0 || timestamp.dwHighDateTime != 0)
            && signer_certificate(countersigner).is_ok()
    })
}

fn signature_status_from_wintrust(status: i32) -> WindowsPacketAdapterSignatureStatus {
    match status {
        TRUST_E_NOSIGNATURE | TRUST_E_BAD_DIGEST => WindowsPacketAdapterSignatureStatus::Invalid,
        CERT_E_CHAINING
        | CERT_E_EXPIRED
        | CERT_E_REVOKED
        | CERT_E_UNTRUSTEDROOT
        | TRUST_E_EXPLICIT_DISTRUST
        | CRYPT_E_SECURITY_SETTINGS => WindowsPacketAdapterSignatureStatus::Untrusted,
        _ => WindowsPacketAdapterSignatureStatus::Unknown,
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let byte = *byte;
        result.push(HEX[usize::from(byte >> 4)] as char);
        result.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    result
}

fn map_file_error(
    kind: WindowsPacketAdapterArtifactKind,
    error: NativeEvidenceError,
) -> WindowsPacketAdapterCollectorError {
    match error {
        NativeEvidenceError::Missing => WindowsPacketAdapterCollectorError::MissingArtifact(kind),
        NativeEvidenceError::Inaccessible => {
            WindowsPacketAdapterCollectorError::InaccessibleArtifact(kind)
        }
        NativeEvidenceError::Invalid | NativeEvidenceError::UntrustedPermissions => {
            WindowsPacketAdapterCollectorError::InvalidArtifact(kind)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn required_path(name: &str) -> PathBuf {
        std::env::var_os(name)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("{name} must point to the pinned Wintun fixture"))
    }

    fn temporary_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "slipstream-wintun-collector-{}-{name}",
            std::process::id()
        ))
    }

    #[test]
    fn pe_parser_is_bounded_and_collector_reports_exact_artifact_failures() {
        let valid_pe = temporary_path("minimal.dll");
        let mut bytes = vec![0u8; 0x86];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        fs::write(&valid_pe, &bytes).expect("write minimal PE fixture");
        let mut file = File::open(&valid_pe).expect("open minimal PE fixture");
        assert_eq!(read_pe_machine(&mut file, bytes.len() as u64), Ok(0x8664));
        drop(file);

        bytes[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        fs::write(&valid_pe, &bytes).expect("overwrite invalid PE fixture");
        let mut file = File::open(&valid_pe).expect("open invalid PE fixture");
        assert_eq!(
            read_pe_machine(&mut file, bytes.len() as u64),
            Err(WindowsPacketAdapterCollectorError::InvalidPe)
        );
        drop(file);
        fs::remove_file(&valid_pe).expect("remove PE fixture");

        let missing = temporary_path("missing.zip");
        let _ = fs::remove_file(&missing);
        assert!(matches!(
            collect_windows_packet_adapter_artifact(
                WindowsPacketAdapterArchitecture::Amd64,
                &missing,
                Path::new("unused-license"),
                Path::new("unused-dll")
            ),
            Err(WindowsPacketAdapterCollectorError::MissingArtifact(
                WindowsPacketAdapterArtifactKind::Archive
            ))
        ));
    }

    #[test]
    fn wintrust_statuses_are_normalized_without_treating_warnings_as_success() {
        assert_eq!(
            signature_status_from_wintrust(TRUST_E_BAD_DIGEST),
            WindowsPacketAdapterSignatureStatus::Invalid
        );
        assert_eq!(
            signature_status_from_wintrust(CERT_E_UNTRUSTEDROOT),
            WindowsPacketAdapterSignatureStatus::Untrusted
        );
        assert_eq!(
            signature_status_from_wintrust(1),
            WindowsPacketAdapterSignatureStatus::Unknown
        );
    }

    #[test]
    fn official_amd64_and_arm64_artifacts_are_admitted_without_loading() {
        if std::env::var_os("SLIPSTREAM_WINDOWS_WINTUN_CI").is_none() {
            return;
        }
        let archive = required_path("SLIPSTREAM_WINTUN_ARCHIVE");
        let license = required_path("SLIPSTREAM_WINTUN_LICENSE");
        let fixtures = [
            (
                WindowsPacketAdapterArchitecture::Amd64,
                required_path("SLIPSTREAM_WINTUN_AMD64_DLL"),
            ),
            (
                WindowsPacketAdapterArchitecture::Arm64,
                required_path("SLIPSTREAM_WINTUN_ARM64_DLL"),
            ),
        ];

        for (architecture, dll) in fixtures {
            let collected =
                collect_windows_packet_adapter_artifact(architecture, &archive, &license, &dll)
                    .unwrap_or_else(|error| panic!("collect {}: {error:?}", architecture.as_str()));
            assert_eq!(
                collected.evidence().signature_status,
                WindowsPacketAdapterSignatureStatus::Valid
            );
            assert!(collected.evidence().timestamped);
            let admission = collected
                .admit()
                .unwrap_or_else(|error| panic!("admit {}: {error:?}", architecture.as_str()));
            assert_eq!(admission.artifact_admission().architecture(), architecture);
            assert_eq!(admission.dll_path(), dll.canonicalize().unwrap());
            assert_eq!(
                admission.retained_dll_length().unwrap(),
                admission.evidence().dll_length
            );
        }

        let original = required_path("SLIPSTREAM_WINTUN_AMD64_DLL");
        let changed = std::env::temp_dir().join(format!(
            "slipstream-wintun-tampered-{}.dll",
            std::process::id()
        ));
        let mut bytes = fs::read(&original).expect("read official DLL fixture");
        let last = bytes.last_mut().expect("official DLL must not be empty");
        *last ^= 1;
        fs::write(&changed, bytes).expect("write tampered DLL fixture");
        let collected = collect_windows_packet_adapter_artifact(
            WindowsPacketAdapterArchitecture::Amd64,
            &archive,
            &license,
            &changed,
        )
        .expect("tampered signed file should still produce rejection evidence");
        assert!(matches!(
            collected.admit(),
            Err(WindowsPacketAdapterErrorCode::DllHashMismatch)
        ));
        fs::remove_file(changed).expect("remove tampered DLL fixture");
    }
}
