fn main() {
    // crypto-ring and send2 cannot be used together
    #[cfg(all(feature = "crypto-ring", feature = "send2",))]
    {
        println!(
            "cargo:warning=ffsend-api: feature 'crypto-ring' and 'send2' cannot be used together"
        );
        println!("cargo:warning=ffsend-api: use 'crypto-openssl' instead or opt out of 'send2'");
    }
}
