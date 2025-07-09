#[cfg(not(fuzzing))]
compile_error!("Fuzz targets need cfg=fuzzing");

#[cfg(not(hashes_fuzz))]
compile_error!("Fuzz targets need cfg=hashes_fuzz");

#[cfg(not(secp256k1_fuzz))]
compile_error!("Fuzz targets need cfg=secp256k1_fuzz");

pub mod sp_code;
