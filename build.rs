fn main() {
    // Require one Send version to be used
    #[cfg(not(any(feature = "send2", feature = "send3")))]
    println!("cargo:warning=ffsend-api: must specify send versions, provide feature 'send2' and/or 'send3'");

    // Require one crypto backend to be used
    #[cfg(not(any(feature = "crypto-ring", feature = "crypto-openssl")))]
    println!("cargo:warning=ffsend-api: must specify crypto backend, provide feature 'crypto-ring' or 'crypto-openssl'");
    #[cfg(all(feature = "crypto-ring", feature = "crypto-openssl"))]
    println!("cargo:warning=ffsend-api: feature 'crypto-ring' and 'crypto-openssl' cannot be used together");

    // crypto-ring and send2 cannot be used together
    #[cfg(all(feature = "crypto-ring", feature = "send2"))]
    {
        println!(
            "cargo:warning=ffsend-api: feature 'crypto-ring' and 'send2' cannot be used together"
        );
        println!("cargo:warning=ffsend-api: use 'crypto-openssl' instead or opt out of 'send2'");
    }
}
