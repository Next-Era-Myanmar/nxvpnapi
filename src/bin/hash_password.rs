use nxvpnapi::crypto::hash_password;

fn main() -> anyhow::Result<()> {
    let password = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "nxvpn123".to_string());
    let hash = hash_password(&password)?;
    println!("{}", hash);
    Ok(())
}
