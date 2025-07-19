#![allow(non_snake_case)]

use dleq::dleq_generate_proof;

use crate::serialization::{GENERATE_PROOF_VECTORS, GenerateTestCase};

fn check_generated_proof(test_case: &GenerateTestCase) {
    let GenerateTestCase {
        point_G,
        scalar_a,
        point_B,
        auxrand_r,
        message,
        result_proof,
        ..
    } = test_case;
    if let (Some(scalar_a), Some(point_B), Some(expected_proof)) = (scalar_a, point_B, result_proof)
    {
        if let Ok(generated_proof) =
            dleq_generate_proof(*scalar_a, *point_B, auxrand_r, *point_G, message.as_ref())
        {
            assert_eq!(generated_proof, *expected_proof);
        } else {
            assert_eq!(expected_proof, &[0u8; 64]);
        }
    }
}

#[test]
fn vector_0_success_case_1() {
    check_generated_proof(&GENERATE_PROOF_VECTORS[0]);
}

#[test]
fn vector_1_success_case_2() {
    check_generated_proof(&GENERATE_PROOF_VECTORS[1]);
}

#[test]
fn vector_2_success_case_3() {
    check_generated_proof(&GENERATE_PROOF_VECTORS[2]);
}

#[test]
fn vector_3_success_case_4() {
    check_generated_proof(&GENERATE_PROOF_VECTORS[3]);
}

#[test]
fn vector_4_success_case_5() {
    check_generated_proof(&GENERATE_PROOF_VECTORS[4]);
}

#[test]
fn vector_5_success_case_6() {
    check_generated_proof(&GENERATE_PROOF_VECTORS[5]);
}

#[test]
fn vector_6_success_case_7() {
    check_generated_proof(&GENERATE_PROOF_VECTORS[6]);
}

#[test]
fn vector_7_success_case_8() {
    check_generated_proof(&GENERATE_PROOF_VECTORS[7]);
}

#[test]
fn vector_8_failure_case_a_eq_0() {
    check_generated_proof(&GENERATE_PROOF_VECTORS[8]);
}

#[test]
fn vector_9_failure_case_a_is_group_order() {
    check_generated_proof(&GENERATE_PROOF_VECTORS[9]);
}

#[test]
fn vector_10_failure_case_b_is_point_at_infinity() {
    check_generated_proof(&GENERATE_PROOF_VECTORS[10]);
}
