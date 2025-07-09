#![cfg_attr(feature = "libfuzzer_fuzz", no_main)]

use bdk_sp::encoding::SilentPaymentCode;
use core::convert::TryFrom;

use sp_fuzz::sp_code::sp_code_parse_run;

#[cfg(feature = "afl")]
#[macro_use]
extern crate afl;
#[cfg(feature = "afl")]
fn main() {
    fuzz!(|data| {
        sp_code_parse_run(data.as_ptr(), data.len());
    });
}

#[cfg(feature = "honggfuzz")]
#[macro_use]
extern crate honggfuzz;
#[cfg(feature = "honggfuzz")]
fn main() {
    loop {
        fuzz!(|data| {
            sp_code_parse_run(data.as_ptr(), data.len());
        });
    }
}

#[cfg(feature = "libfuzzer_fuzz")]
#[macro_use]
extern crate libfuzzer_sys;
#[cfg(feature = "libfuzzer_fuzz")]
fuzz_target!(|data: &[u8]| {
    sp_code_parse_run(data.as_ptr(), data.len());
});

#[cfg(feature = "stdin_fuzz")]
fn main() {
    use std::io::Read;

    let mut data = Vec::with_capacity(1023);
    std::io::stdin().read_to_end(&mut data).unwrap();
    sp_code_parse_run(data.as_ptr(), data.len());
}
