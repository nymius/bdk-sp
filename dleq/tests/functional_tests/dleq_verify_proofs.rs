use crate::serialization::{VERIFY_PROOF_VECTORS, VerifyTestCase};
use dleq::dleq_verify_proof;

fn check_generated_proof(test_case: &VerifyTestCase) {
    let VerifyTestCase {
        point_G,
        point_A,
        point_B,
        point_C,
        proof,
        message,
        result_success,
        ..
    } = test_case;
    if let Ok(given_result) = dleq_verify_proof(
        *point_A,
        *point_B,
        *point_C,
        proof,
        *point_G,
        message.as_ref(),
    ) {
        assert_eq!(*result_success, given_result);
    } else {
        assert!(!result_success);
    }
}

#[test]
fn test_0_success_case_1() {
    check_generated_proof(&VERIFY_PROOF_VECTORS[0]);
}

#[test]
fn test_1_success_case_2() {
    check_generated_proof(&VERIFY_PROOF_VECTORS[1]);
}

#[test]
fn test_2_success_case_3() {
    check_generated_proof(&VERIFY_PROOF_VECTORS[2]);
}

#[test]
fn test_3_success_case_4() {
    check_generated_proof(&VERIFY_PROOF_VECTORS[3]);
}

#[test]
fn test_4_success_case_5() {
    check_generated_proof(&VERIFY_PROOF_VECTORS[4]);
}

#[test]
fn test_5_success_case_6() {
    check_generated_proof(&VERIFY_PROOF_VECTORS[5]);
}

#[test]
fn test_6_success_case_7() {
    check_generated_proof(&VERIFY_PROOF_VECTORS[6]);
}

#[test]
fn test_7_success_case_8() {
    check_generated_proof(&VERIFY_PROOF_VECTORS[7]);
}

#[test]
fn test_8_swapped_points_case_1() {
    check_generated_proof(&VERIFY_PROOF_VECTORS[8]);
}

#[test]
fn test_9_swapped_points_case_2() {
    check_generated_proof(&VERIFY_PROOF_VECTORS[9]);
}

#[test]
fn test_10_swapped_points_case_3() {
    check_generated_proof(&VERIFY_PROOF_VECTORS[10]);
}

#[test]
fn test_11_swapped_points_case_4() {
    check_generated_proof(&VERIFY_PROOF_VECTORS[11]);
}

#[test]
fn test_12_swapped_points_case_5() {
    check_generated_proof(&VERIFY_PROOF_VECTORS[12]);
}

#[test]
fn test_13_tampered_proof_random_bit_flip() {
    check_generated_proof(&VERIFY_PROOF_VECTORS[13]);
}

#[test]
fn test_14_tampered_message_random_bit_flip() {
    check_generated_proof(&VERIFY_PROOF_VECTORS[14]);
}
