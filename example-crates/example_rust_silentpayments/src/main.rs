use std::error::Error;
use bdk_testenv::TestEnv;

fn main() -> Result<(), Box<dyn Error>> {
    let env = TestEnv::new()?;
    let rpc_client = env.rpc_client();
    println!("Hello, world!");
    Ok(())
}
