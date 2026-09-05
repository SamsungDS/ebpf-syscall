// SPDX-License-Identifier: Apache-2.0
//! Checked translation between kvio's command stream and fio v3 iologs.
//!
//! This crate contains no device I/O. It proves facts about a finite requested
//! command stream, not about fio, Linux, an NVMe controller, or performance.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;

pub const FIO_V3_HEADER: &str = "fio version 3 iolog";
const NS_PER_US: u64 = 1_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Operation {
    Read,
    Write,
    Sync,
    Datasync,
}

impl Operation {
    fn fio_name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Sync => "sync",
            Self::Datasync => "datasync",
        }
    }

    fn is_data(self) -> bool {
        matches!(self, Self::Read | Self::Write)
    }
}

// Keep fields alphabetized. serde_json then matches Python's sort_keys=True
// encoding used for normalized_stream_sha256 in certificate.json.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Command {
    pub at_ns: u64,
    pub length_bytes: u64,
    pub offset_bytes: u64,
    pub op: Operation,
    pub seq: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Workload {
    pub schema_version: u32,
    pub commands: Vec<Command>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SourceCertificate {
    pub schema_version: u32,
    pub equivalence_level: String,
    pub source_command_count: usize,
    pub emitted_command_count: usize,
    pub operation_offset_length_sequence_equal: bool,
    pub normalized_stream_sha256: String,
    pub emitted_iolog_sha256: String,
    pub maximum_timestamp_quantization_error_ns: u64,
    pub lba_bytes: u64,
    pub capture_drops: u64,
    pub unsupported_commands_omitted: usize,
    pub performance_equivalence_claimed: bool,
    pub runtime_device_validation: Option<RuntimeDeviceValidation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LatencyDistribution {
    pub sample_count: usize,
    pub p50_us: Option<f64>,
    pub p99_us: Option<f64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TimingError {
    pub p50: Option<f64>,
    pub p99: Option<f64>,
    pub max: Option<f64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionLatency {
    pub source: LatencyDistribution,
    pub replay: LatencyDistribution,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionPairing {
    pub source_complete: bool,
    pub replay_complete: bool,
    pub per_command_compared: bool,
    pub absolute_error_p50_us: Option<f64>,
    pub absolute_error_p99_us: Option<f64>,
    pub absolute_error_max_us: Option<f64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDeviceValidation {
    pub schema_version: u32,
    pub replay_capture_sha256: String,
    pub source_command_count: usize,
    pub replay_command_count: usize,
    pub source_capture_complete: bool,
    pub replay_capture_complete: bool,
    pub command_count_equal: bool,
    pub operation_sequence_equal: bool,
    pub offset_sequence_equal: bool,
    pub length_sequence_equal: bool,
    pub tuple_sequence_equal: bool,
    pub device_stream_equal: bool,
    pub timing_error_us: TimingError,
    pub completion_latency_us: CompletionLatency,
    pub completion_pairing: CompletionPairing,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Constraints {
    pub region_bytes: Option<u64>,
    pub max_transfer_bytes: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FioCommand {
    pub at_us: u64,
    pub length_bytes: u64,
    pub offset_bytes: u64,
    pub op: Operation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedIolog {
    pub filename: String,
    pub commands: Vec<FioCommand>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidationCertificate {
    pub schema_version: u32,
    pub verifier: &'static str,
    pub equivalence_level: &'static str,
    pub command_count: usize,
    pub operation_offset_length_sequence_equal: bool,
    pub sequence_numbers_contiguous: bool,
    pub timestamps_nondecreasing: bool,
    pub maximum_timestamp_quantization_error_ns: u64,
    pub lba_bytes: u64,
    pub source_capture_complete: bool,
    pub source_capture_drops: u64,
    pub source_unsupported_commands_omitted: usize,
    pub device_region_checked: bool,
    pub transfer_limit_checked: bool,
    pub source_certificate_consistent: bool,
    pub performance_equivalence_claimed: bool,
    pub runtime_device_validation: Option<RuntimeDeviceValidation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrError(String);

impl IrError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for IrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for IrError {}

pub fn align_up(value: u64, alignment: u64) -> Result<u64, IrError> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(IrError::new("alignment must be a positive power of two"));
    }
    let mask = alignment - 1;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or_else(|| IrError::new("aligned value overflows u64"))
}

pub fn byte_offset(slba: u64, lba_bytes: u64) -> Result<u64, IrError> {
    validate_lba(lba_bytes)?;
    slba.checked_mul(lba_bytes)
        .ok_or_else(|| IrError::new("LBA byte offset overflows u64"))
}

pub fn quantize_timestamp_ns(at_ns: u64) -> (u64, u64) {
    (at_ns / NS_PER_US, at_ns % NS_PER_US)
}

fn validate_lba(lba_bytes: u64) -> Result<(), IrError> {
    if lba_bytes == 0 || !lba_bytes.is_power_of_two() {
        return Err(IrError::new(
            "logical block size must be a positive power of two",
        ));
    }
    Ok(())
}

fn validate_transfer_limit(limit: u64, lba_bytes: u64) -> Result<(), IrError> {
    if limit == 0 || !limit.is_multiple_of(lba_bytes) {
        return Err(IrError::new(
            "transfer limit must be nonzero and block aligned",
        ));
    }
    Ok(())
}

fn validate_command(
    command: &Command,
    expected_seq: usize,
    lba_bytes: u64,
    constraints: Constraints,
) -> Result<(), IrError> {
    if command.seq != expected_seq as u64 {
        return Err(IrError::new(format!(
            "command {} has sequence {}, expected {}",
            expected_seq, command.seq, expected_seq
        )));
    }
    if !command.op.is_data() {
        if command.offset_bytes != 0 || command.length_bytes != 0 {
            return Err(IrError::new(format!(
                "command {} sync operation must have zero offset and length",
                expected_seq
            )));
        }
        return Ok(());
    }
    if command.length_bytes == 0 {
        return Err(IrError::new(format!(
            "command {} has zero length",
            expected_seq
        )));
    }
    if !command.offset_bytes.is_multiple_of(lba_bytes)
        || !command.length_bytes.is_multiple_of(lba_bytes)
    {
        return Err(IrError::new(format!(
            "command {} is not aligned to {} bytes",
            expected_seq, lba_bytes
        )));
    }
    if let Some(limit) = constraints.max_transfer_bytes {
        validate_transfer_limit(limit, lba_bytes)?;
        if command.length_bytes > limit {
            return Err(IrError::new(format!(
                "command {} exceeds the {}-byte transfer limit",
                expected_seq, limit
            )));
        }
    }
    let end = command
        .offset_bytes
        .checked_add(command.length_bytes)
        .ok_or_else(|| IrError::new(format!("command {} range overflows u64", expected_seq)))?;
    if let Some(region) = constraints.region_bytes {
        if end > region {
            return Err(IrError::new(format!(
                "command {} ends beyond the {}-byte device region",
                expected_seq, region
            )));
        }
    }
    Ok(())
}

pub fn validate_workload(
    workload: &Workload,
    lba_bytes: u64,
    constraints: Constraints,
) -> Result<(), IrError> {
    if workload.schema_version != 1 {
        return Err(IrError::new("unsupported workload schema"));
    }
    validate_lba(lba_bytes)?;
    if constraints
        .region_bytes
        .is_some_and(|region| region == 0 || !region.is_multiple_of(lba_bytes))
    {
        return Err(IrError::new(
            "device region must be nonzero and block aligned",
        ));
    }
    if let Some(limit) = constraints.max_transfer_bytes {
        validate_transfer_limit(limit, lba_bytes)?;
    }
    let mut previous_timestamp = None;
    for (index, command) in workload.commands.iter().enumerate() {
        validate_command(command, index, lba_bytes, constraints)?;
        if previous_timestamp.is_some_and(|previous| command.at_ns < previous) {
            return Err(IrError::new(format!(
                "command {} timestamp moves backwards",
                index
            )));
        }
        previous_timestamp = Some(command.at_ns);
    }
    Ok(())
}

pub fn split_extent(
    offset_bytes: u64,
    logical_bytes: u64,
    lba_bytes: u64,
    transfer_limit: u64,
) -> Result<Vec<(u64, u64)>, IrError> {
    validate_lba(lba_bytes)?;
    validate_transfer_limit(transfer_limit, lba_bytes)?;
    if !offset_bytes.is_multiple_of(lba_bytes) {
        return Err(IrError::new("extent offset is not block aligned"));
    }
    if logical_bytes == 0 {
        return Ok(Vec::new());
    }
    let mut remaining = align_up(logical_bytes, lba_bytes)?;
    offset_bytes
        .checked_add(remaining)
        .ok_or_else(|| IrError::new("extent range overflows u64"))?;

    let mut result = Vec::new();
    let mut offset = offset_bytes;
    while remaining != 0 {
        let length = remaining.min(transfer_limit);
        result.push((offset, length));
        offset = offset
            .checked_add(length)
            .ok_or_else(|| IrError::new("split offset overflows u64"))?;
        remaining -= length;
    }
    Ok(result)
}

pub fn emit_fio_iolog(commands: &[Command], filename: &str) -> Result<String, IrError> {
    if filename.is_empty() || filename.chars().any(char::is_whitespace) {
        return Err(IrError::new(
            "fio target must be nonempty and contain no whitespace",
        ));
    }
    let workload = Workload {
        schema_version: 1,
        commands: commands.to_vec(),
    };
    validate_workload(&workload, 1, Constraints::default())?;

    let mut output = String::new();
    output.push_str(FIO_V3_HEADER);
    output.push('\n');
    output.push_str(&format!("0 {filename} add\n0 {filename} open\n"));
    for command in commands {
        let (at_us, _) = quantize_timestamp_ns(command.at_ns);
        if command.op.is_data() {
            output.push_str(&format!(
                "{at_us} {filename} {} {} {}\n",
                command.op.fio_name(),
                command.offset_bytes,
                command.length_bytes
            ));
        } else {
            output.push_str(&format!("{at_us} {filename} {}\n", command.op.fio_name()));
        }
    }
    let close_us = commands
        .last()
        .map(|command| quantize_timestamp_ns(command.at_ns).0)
        .unwrap_or(0);
    output.push_str(&format!("{close_us} {filename} close\n"));
    Ok(output)
}

fn parse_u64(value: &str, line: usize, field: &str) -> Result<u64, IrError> {
    value
        .parse()
        .map_err(|_| IrError::new(format!("line {} has invalid {}", line, field)))
}

pub fn parse_fio_iolog(text: &str) -> Result<ParsedIolog, IrError> {
    let mut lines = text.lines();
    if lines.next() != Some(FIO_V3_HEADER) {
        return Err(IrError::new("invalid fio v3 header"));
    }

    let mut filename: Option<String> = None;
    let mut saw_add = false;
    let mut saw_open = false;
    let mut saw_close = false;
    let mut commands = Vec::new();
    for (index, line) in lines.enumerate() {
        let line_number = index + 2;
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 3 {
            return Err(IrError::new(format!("line {} is incomplete", line_number)));
        }
        let at_us = parse_u64(fields[0], line_number, "timestamp")?;
        if filename.as_deref().is_some_and(|name| name != fields[1]) {
            return Err(IrError::new(format!(
                "line {} changes the fio target",
                line_number
            )));
        }
        filename.get_or_insert_with(|| fields[1].to_owned());
        match (fields[2], fields.len()) {
            ("add", 3) if !saw_add && !saw_open && commands.is_empty() => saw_add = true,
            ("open", 3) if saw_add && !saw_open && commands.is_empty() => saw_open = true,
            ("close", 3) if saw_open && !saw_close => {
                saw_close = true;
                let expected = commands
                    .last()
                    .map(|command: &FioCommand| command.at_us)
                    .unwrap_or(0);
                if at_us != expected {
                    return Err(IrError::new(
                        "close timestamp does not match the last command",
                    ));
                }
            }
            ("read", 5) | ("write", 5) if saw_open && !saw_close => {
                let op = if fields[2] == "read" {
                    Operation::Read
                } else {
                    Operation::Write
                };
                commands.push(FioCommand {
                    at_us,
                    length_bytes: parse_u64(fields[4], line_number, "length")?,
                    offset_bytes: parse_u64(fields[3], line_number, "offset")?,
                    op,
                });
            }
            ("sync", 3) | ("datasync", 3) if saw_open && !saw_close => {
                commands.push(FioCommand {
                    at_us,
                    length_bytes: 0,
                    offset_bytes: 0,
                    op: if fields[2] == "sync" {
                        Operation::Sync
                    } else {
                        Operation::Datasync
                    },
                });
            }
            _ => {
                return Err(IrError::new(format!(
                    "line {} has an invalid action or ordering",
                    line_number
                )));
            }
        }
    }
    if !saw_add || !saw_open || !saw_close {
        return Err(IrError::new(
            "iolog must contain ordered add, open, and close actions",
        ));
    }
    if commands
        .windows(2)
        .any(|pair| pair[1].at_us < pair[0].at_us)
    {
        return Err(IrError::new("iolog command timestamps move backwards"));
    }
    Ok(ParsedIolog {
        filename: filename.expect("file actions establish a filename"),
        commands,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn finite_nonnegative(value: f64) -> bool {
    value.is_finite() && value >= 0.0
}

fn validate_latency_distribution(
    distribution: &LatencyDistribution,
    name: &str,
) -> Result<(), IrError> {
    match (distribution.p50_us, distribution.p99_us) {
        (None, None) if distribution.sample_count == 0 => Ok(()),
        (Some(p50), Some(p99))
            if distribution.sample_count > 0
                && finite_nonnegative(p50)
                && finite_nonnegative(p99)
                && p50 <= p99 =>
        {
            Ok(())
        }
        _ => Err(IrError::new(format!(
            "{name} completion-latency distribution is inconsistent"
        ))),
    }
}

fn validate_error_triplet(
    p50: Option<f64>,
    p99: Option<f64>,
    maximum: Option<f64>,
    required: bool,
    name: &str,
) -> Result<(), IrError> {
    match (p50, p99, maximum) {
        (None, None, None) if !required => Ok(()),
        (Some(p50), Some(p99), Some(maximum))
            if required
                && finite_nonnegative(p50)
                && finite_nonnegative(p99)
                && finite_nonnegative(maximum)
                && p50 <= p99
                && p99 <= maximum =>
        {
            Ok(())
        }
        _ => Err(IrError::new(format!(
            "{name} error summary is inconsistent"
        ))),
    }
}

fn validate_runtime_device(
    runtime: &RuntimeDeviceValidation,
    workload: &Workload,
    source_complete: bool,
) -> Result<(), IrError> {
    if runtime.schema_version != 1 {
        return Err(IrError::new("unsupported runtime validation schema"));
    }
    if !is_sha256(&runtime.replay_capture_sha256) {
        return Err(IrError::new("runtime replay digest is not SHA-256"));
    }
    if runtime.source_command_count != workload.commands.len() {
        return Err(IrError::new(
            "runtime source command count disagrees with workload",
        ));
    }
    if runtime.command_count_equal != (runtime.source_command_count == runtime.replay_command_count)
    {
        return Err(IrError::new(
            "runtime command-count verdict is inconsistent",
        ));
    }
    if !runtime.command_count_equal
        && (runtime.operation_sequence_equal
            || runtime.offset_sequence_equal
            || runtime.length_sequence_equal)
    {
        return Err(IrError::new(
            "runtime sequence verdict cannot pass with unequal counts",
        ));
    }
    if runtime.source_capture_complete != source_complete {
        return Err(IrError::new(
            "runtime source-completeness verdict is inconsistent",
        ));
    }
    let components_equal = runtime.operation_sequence_equal
        && runtime.offset_sequence_equal
        && runtime.length_sequence_equal;
    if runtime.tuple_sequence_equal != (runtime.command_count_equal && components_equal) {
        return Err(IrError::new("runtime tuple verdict is inconsistent"));
    }
    let stream_equal = runtime.source_capture_complete
        && runtime.replay_capture_complete
        && runtime.tuple_sequence_equal;
    if runtime.device_stream_equal != stream_equal {
        return Err(IrError::new(
            "runtime device-stream verdict is inconsistent",
        ));
    }
    validate_error_triplet(
        runtime.timing_error_us.p50,
        runtime.timing_error_us.p99,
        runtime.timing_error_us.max,
        runtime.command_count_equal && runtime.source_command_count > 0,
        "runtime issue-timing",
    )?;
    validate_latency_distribution(&runtime.completion_latency_us.source, "source")?;
    validate_latency_distribution(&runtime.completion_latency_us.replay, "replay")?;
    if runtime.completion_latency_us.source.sample_count > runtime.source_command_count
        || runtime.completion_latency_us.replay.sample_count > runtime.replay_command_count
    {
        return Err(IrError::new(
            "runtime completion sample count exceeds command count",
        ));
    }
    if (runtime.completion_pairing.source_complete
        && runtime.completion_latency_us.source.sample_count != runtime.source_command_count)
        || (runtime.completion_pairing.replay_complete
            && runtime.completion_latency_us.replay.sample_count != runtime.replay_command_count)
    {
        return Err(IrError::new(
            "complete runtime pairing must cover every command",
        ));
    }
    let should_compare_completions = runtime.tuple_sequence_equal
        && runtime.completion_pairing.source_complete
        && runtime.completion_pairing.replay_complete
        && runtime.source_command_count > 0;
    if runtime.completion_pairing.per_command_compared != should_compare_completions {
        return Err(IrError::new(
            "runtime per-command completion verdict is inconsistent",
        ));
    }
    validate_error_triplet(
        runtime.completion_pairing.absolute_error_p50_us,
        runtime.completion_pairing.absolute_error_p99_us,
        runtime.completion_pairing.absolute_error_max_us,
        should_compare_completions,
        "runtime completion-latency",
    )
}

pub fn validate_translation(
    workload: &Workload,
    iolog: &str,
    source: &SourceCertificate,
    constraints: Constraints,
) -> Result<ValidationCertificate, IrError> {
    validate_workload(workload, source.lba_bytes, constraints)?;
    if source.schema_version != 1 {
        return Err(IrError::new("unsupported source certificate schema"));
    }
    if source.performance_equivalence_claimed {
        return Err(IrError::new(
            "source certificate must not claim performance equivalence",
        ));
    }
    if !source.operation_offset_length_sequence_equal {
        return Err(IrError::new(
            "source certificate reports a failed translation",
        ));
    }
    if source.source_command_count != workload.commands.len()
        || source.emitted_command_count != workload.commands.len()
    {
        return Err(IrError::new(
            "source certificate command count disagrees with workload",
        ));
    }
    let source_complete = source.capture_drops == 0 && source.unsupported_commands_omitted == 0;
    let expected_level = if source_complete {
        "stream-translation"
    } else {
        "partial-stream-translation"
    };
    if source.equivalence_level != expected_level {
        return Err(IrError::new(
            "source equivalence level disagrees with omitted commands or drops",
        ));
    }
    let normalized = serde_json::to_vec(&workload.commands)
        .map_err(|error| IrError::new(format!("cannot serialize workload: {error}")))?;
    if sha256_hex(&normalized) != source.normalized_stream_sha256 {
        return Err(IrError::new(
            "normalized workload hash disagrees with certificate",
        ));
    }
    if sha256_hex(iolog.as_bytes()) != source.emitted_iolog_sha256 {
        return Err(IrError::new("iolog hash disagrees with certificate"));
    }

    let parsed = parse_fio_iolog(iolog)?;
    let expected: Vec<_> = workload
        .commands
        .iter()
        .map(|command| FioCommand {
            at_us: quantize_timestamp_ns(command.at_ns).0,
            length_bytes: command.length_bytes,
            offset_bytes: command.offset_bytes,
            op: command.op,
        })
        .collect();
    if parsed.commands != expected {
        return Err(IrError::new(
            "fio iolog does not preserve the command stream",
        ));
    }
    if emit_fio_iolog(&workload.commands, &parsed.filename)? != iolog {
        return Err(IrError::new(
            "fio iolog is not the canonical encoding of the workload",
        ));
    }
    let maximum_error = workload
        .commands
        .iter()
        .map(|command| quantize_timestamp_ns(command.at_ns).1)
        .max()
        .unwrap_or(0);
    if maximum_error != source.maximum_timestamp_quantization_error_ns {
        return Err(IrError::new(
            "timestamp rounding bound disagrees with source certificate",
        ));
    }
    if let Some(runtime) = &source.runtime_device_validation {
        validate_runtime_device(runtime, workload, source_complete)?;
    }

    Ok(ValidationCertificate {
        schema_version: 1,
        verifier: "kvio-ir",
        equivalence_level: "finite-stream-translation",
        command_count: workload.commands.len(),
        operation_offset_length_sequence_equal: true,
        sequence_numbers_contiguous: true,
        timestamps_nondecreasing: true,
        maximum_timestamp_quantization_error_ns: maximum_error,
        lba_bytes: source.lba_bytes,
        source_capture_complete: source_complete,
        source_capture_drops: source.capture_drops,
        source_unsupported_commands_omitted: source.unsupported_commands_omitted,
        device_region_checked: constraints.region_bytes.is_some(),
        transfer_limit_checked: constraints.max_transfer_bytes.is_some(),
        source_certificate_consistent: true,
        performance_equivalence_claimed: false,
        runtime_device_validation: source.runtime_device_validation.clone(),
    })
}

#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn timestamp_rounding_is_below_one_microsecond() {
        let timestamp = u64::from(kani::any::<u32>());
        let (microseconds, remainder) = quantize_timestamp_ns(timestamp);
        assert!(remainder < NS_PER_US);
        assert_eq!(timestamp, microseconds * NS_PER_US + remainder);
    }

    #[kani::proof]
    fn byte_offset_matches_checked_multiplication() {
        let slba = if kani::any::<bool>() {
            u64::from(kani::any::<u32>())
        } else {
            u64::MAX - u64::from(kani::any::<u16>())
        };
        let exponent: u8 = kani::any();
        kani::assume(exponent < 16);
        let lba_bytes = 1_u64 << exponent;
        assert_eq!(
            byte_offset(slba, lba_bytes).ok(),
            slba.checked_mul(lba_bytes)
        );
    }

    #[kani::proof]
    fn alignment_never_wraps() {
        let value = if kani::any::<bool>() {
            u64::from(kani::any::<u32>())
        } else {
            u64::MAX - u64::from(kani::any::<u16>())
        };
        let exponent: u8 = kani::any();
        kani::assume(exponent < 16);
        let alignment = 1_u64 << exponent;
        match align_up(value, alignment) {
            Ok(aligned) => {
                assert!(aligned >= value);
                assert!(aligned.is_multiple_of(alignment));
                assert!(aligned - value < alignment);
            }
            Err(_) => assert!(value.checked_add(alignment - 1).is_none()),
        }
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn bounded_split_has_no_gaps_or_oversized_commands() {
        let lba_exponent: u8 = kani::any();
        let limit_blocks: u8 = kani::any();
        let logical_bytes: u16 = kani::any();
        kani::assume(lba_exponent < 4);
        kani::assume(limit_blocks > 0 && limit_blocks <= 8);
        let lba_bytes = 1_u64 << lba_exponent;
        let limit = u64::from(limit_blocks) * lba_bytes;
        let rounded = align_up(u64::from(logical_bytes), lba_bytes).unwrap();
        kani::assume(rounded / limit <= 8);
        let commands = split_extent(0, u64::from(logical_bytes), lba_bytes, limit).unwrap();
        let mut next_offset = 0;
        let mut total = 0;
        for (offset, length) in commands {
            assert_eq!(offset, next_offset);
            assert!(length > 0 && length <= limit);
            assert!(length.is_multiple_of(lba_bytes));
            next_offset += length;
            total += length;
        }
        assert_eq!(total, rounded);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn command(seq: u64, at_ns: u64, op: Operation, offset: u64, length: u64) -> Command {
        Command {
            at_ns,
            length_bytes: length,
            offset_bytes: offset,
            op,
            seq,
        }
    }

    #[test]
    fn semantic_comparison_detects_a_changed_offset() {
        let commands = vec![command(0, 1_999, Operation::Read, 4096, 4096)];
        let mut iolog = emit_fio_iolog(&commands, "/dev/source").unwrap();
        iolog = iolog.replace("read 4096 4096", "read 8192 4096");
        let parsed = parse_fio_iolog(&iolog).unwrap();
        assert_ne!(parsed.commands[0].offset_bytes, commands[0].offset_bytes);
    }

    #[test]
    fn workload_rejects_noncontiguous_sequence_numbers() {
        let workload = Workload {
            schema_version: 1,
            commands: vec![command(4, 0, Operation::Read, 0, 4096)],
        };
        assert!(validate_workload(&workload, 4096, Constraints::default()).is_err());
    }

    #[test]
    fn workload_enforces_declared_device_and_transfer_bounds() {
        let workload = Workload {
            schema_version: 1,
            commands: vec![command(0, 0, Operation::Read, 4096, 8192)],
        };
        let region_too_small = Constraints {
            region_bytes: Some(8192),
            max_transfer_bytes: None,
        };
        assert!(validate_workload(&workload, 4096, region_too_small).is_err());
        let transfer_too_small = Constraints {
            region_bytes: Some(16384),
            max_transfer_bytes: Some(4096),
        };
        assert!(validate_workload(&workload, 4096, transfer_too_small).is_err());
    }

    #[test]
    fn arithmetic_rejects_u64_overflow() {
        assert!(align_up(u64::MAX, 4096).is_err());
        assert!(byte_offset(u64::MAX, 4096).is_err());
        assert!(split_extent(u64::MAX - 4095, 8192, 4096, 4096).is_err());
    }

    proptest! {
        #[test]
        fn alignment_is_minimal_and_aligned(value in 0_u64..=u32::MAX as u64,
                                             exponent in 0_u8..16) {
            let alignment = 1_u64 << exponent;
            let aligned = align_up(value, alignment).unwrap();
            prop_assert!(aligned >= value);
            prop_assert!(aligned.is_multiple_of(alignment));
            prop_assert!(aligned - value < alignment);
        }

        #[test]
        fn split_is_contiguous_and_covers_the_rounded_extent(
            offset_blocks in 0_u32..100_000,
            logical_bytes in 0_u32..1_000_000,
            lba_exponent in 0_u8..13,
            limit_blocks in 1_u16..256,
        ) {
            let lba_bytes = 1_u64 << lba_exponent;
            let offset = u64::from(offset_blocks) * lba_bytes;
            let limit = u64::from(limit_blocks) * lba_bytes;
            let commands = split_extent(offset, u64::from(logical_bytes), lba_bytes, limit).unwrap();
            let expected = align_up(u64::from(logical_bytes), lba_bytes).unwrap();
            let mut next = offset;
            let mut total = 0;
            for (command_offset, length) in commands {
                prop_assert_eq!(command_offset, next);
                prop_assert!(length > 0 && length <= limit);
                prop_assert!(length.is_multiple_of(lba_bytes));
                next += length;
                total += length;
            }
            prop_assert_eq!(total, expected);
        }

        #[test]
        fn fio_round_trip_preserves_bounded_stream(
            specs in prop::collection::vec((0_u32..10_000, any::<bool>(),
                                             0_u16..4_096, 1_u16..64), 0..24)
        ) {
            let mut at_ns = 0_u64;
            let commands: Vec<_> = specs.into_iter().enumerate().map(
                |(seq, (delta, write, offset_blocks, length_blocks))| {
                    at_ns += u64::from(delta);
                    command(
                        seq as u64,
                        at_ns,
                        if write { Operation::Write } else { Operation::Read },
                        u64::from(offset_blocks) * 512,
                        u64::from(length_blocks) * 512,
                    )
                }
            ).collect();
            let iolog = emit_fio_iolog(&commands, "/dev/source").unwrap();
            let parsed = parse_fio_iolog(&iolog).unwrap();
            let expected: Vec<_> = commands.iter().map(|source| FioCommand {
                at_us: source.at_ns / NS_PER_US,
                length_bytes: source.length_bytes,
                offset_bytes: source.offset_bytes,
                op: source.op,
            }).collect();
            prop_assert_eq!(parsed.commands, expected);
        }
    }
}
