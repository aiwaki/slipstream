use slipstream_windows_adapter::service_host::{
    parse_windows_service_host_arguments, WindowsServiceHostFailureCode,
    WindowsServiceHostFailureV1,
};
use std::io::Write;

#[cfg(windows)]
const EXIT_SUCCESS: i32 = 0;
const EXIT_INVALID_ARGUMENTS: i32 = 2;
#[cfg(windows)]
const EXIT_MANAGEMENT_FAILURE: i32 = 3;
const EXIT_SERVICE_FAILURE: i32 = 4;

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let arguments = match collect_arguments() {
        Ok(arguments) => arguments,
        Err(failure) => return emit_failure(&failure, EXIT_INVALID_ARGUMENTS),
    };
    let invocation = match parse_windows_service_host_arguments(&arguments) {
        Ok(invocation) => invocation,
        Err(error) => {
            let failure = WindowsServiceHostFailureV1::new(
                WindowsServiceHostFailureCode::InvalidArguments,
                error.to_string(),
            );
            return emit_failure(&failure, EXIT_INVALID_ARGUMENTS);
        }
    };

    run_platform(invocation)
}

fn collect_arguments() -> Result<Vec<String>, WindowsServiceHostFailureV1> {
    std::env::args_os()
        .skip(1)
        .map(|argument| {
            argument.into_string().map_err(|_| {
                WindowsServiceHostFailureV1::new(
                    WindowsServiceHostFailureCode::InvalidArguments,
                    "Windows service host arguments must be valid Unicode",
                )
            })
        })
        .collect()
}

#[cfg(windows)]
fn run_platform(
    invocation: slipstream_windows_adapter::service_host::WindowsServiceHostInvocation,
) -> i32 {
    use slipstream_windows_adapter::service_host::execute_windows_service_host;

    let service_mode = matches!(
        &invocation,
        slipstream_windows_adapter::service_host::WindowsServiceHostInvocation::Service
    );
    match execute_windows_service_host(invocation) {
        Ok(Some(result)) => match emit_result(&result) {
            Ok(()) => EXIT_SUCCESS,
            Err(failure) => emit_failure(&failure, EXIT_MANAGEMENT_FAILURE),
        },
        Ok(None) => EXIT_SUCCESS,
        Err(error) => {
            let failure = WindowsServiceHostFailureV1::new(error.failure_code(), error.to_string());
            emit_failure(
                &failure,
                if service_mode {
                    EXIT_SERVICE_FAILURE
                } else {
                    EXIT_MANAGEMENT_FAILURE
                },
            )
        }
    }
}

#[cfg(not(windows))]
fn run_platform(
    _invocation: slipstream_windows_adapter::service_host::WindowsServiceHostInvocation,
) -> i32 {
    let failure = WindowsServiceHostFailureV1::new(
        WindowsServiceHostFailureCode::UnsupportedPlatform,
        "the Slipstream Windows service host requires Windows",
    );
    emit_failure(&failure, EXIT_SERVICE_FAILURE)
}

#[cfg(windows)]
fn emit_result(
    result: &slipstream_windows_adapter::service_host::WindowsServiceManagementResultV1,
) -> Result<(), WindowsServiceHostFailureV1> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, result).map_err(|_| {
        WindowsServiceHostFailureV1::new(
            WindowsServiceHostFailureCode::OutputFailed,
            "Windows service management result could not be written",
        )
    })?;
    writeln!(output).map_err(|_| {
        WindowsServiceHostFailureV1::new(
            WindowsServiceHostFailureCode::OutputFailed,
            "Windows service management result could not be written",
        )
    })
}

fn emit_failure(failure: &WindowsServiceHostFailureV1, exit_code: i32) -> i32 {
    let stderr = std::io::stderr();
    let mut output = stderr.lock();
    if serde_json::to_writer(&mut output, failure).is_ok() {
        let _ = writeln!(output);
    }
    exit_code
}
