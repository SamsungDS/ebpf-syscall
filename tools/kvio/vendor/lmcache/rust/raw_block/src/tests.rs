// SPDX-License-Identifier: Apache-2.0

use super::{check_nvme_ioctl_result, is_retryable_regular_short_io, placement_id_to_u16};

#[test]
fn check_nvme_ioctl_result_accepts_success() {
    assert!(check_nvme_ioctl_result(0, "NVMe ioctl failed").is_ok());
}

#[test]
fn check_nvme_ioctl_result_rejects_nvme_status() {
    assert!(check_nvme_ioctl_result(1, "NVMe ioctl failed").is_err());
}

#[test]
fn placement_id_to_u16_accepts_valid_bounds() {
    assert_eq!(placement_id_to_u16(1).unwrap(), 1);
    assert_eq!(placement_id_to_u16(65535).unwrap(), 65535);
}

#[test]
fn placement_id_to_u16_rejects_reserved_and_out_of_range_values() {
    assert!(placement_id_to_u16(0).is_err());
    assert!(placement_id_to_u16(-1).is_err());
    assert!(placement_id_to_u16(65536).is_err());
}

#[test]
fn regular_io_retries_only_positive_short_completions() {
    assert!(!is_retryable_regular_short_io(-5, 4096, false));
    assert!(!is_retryable_regular_short_io(0, 4096, false));
    assert!(is_retryable_regular_short_io(2048, 4096, false));
    assert!(!is_retryable_regular_short_io(4096, 4096, false));
    assert!(!is_retryable_regular_short_io(2048, 4096, true));
}
