use bdk_sp::encoding::SilentPaymentCode;
use core::convert::TryFrom;

#[inline]
pub fn do_test(data: &[u8]) {
    if let Ok(received_sp_code) = std::str::from_utf8(data) {
        if let Ok(sp_code) = SilentPaymentCode::try_from(received_sp_code) {
            let produced_sp_code = sp_code.to_string();
            assert_eq!(received_sp_code, produced_sp_code);
        }
    }
}
pub fn sp_code_parse_test(data: &[u8]) {
    do_test(data);
}

#[unsafe(no_mangle)]
pub extern "C" fn sp_code_parse_run(data: *const u8, datalen: usize) {
    do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
