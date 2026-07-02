use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Where to write the secret seed (created 0600 on Unix).
    #[arg(long, default_value = "sentinel-audit.key")]
    key: PathBuf,
    /// Where to write the public key (defaults to `<key>.pub`).
    #[arg(long = "pub")]
    public: Option<PathBuf>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let public = args
        .public
        .unwrap_or_else(|| PathBuf::from(format!("{}.pub", args.key.display())));
    let key = sentinel_audit::generate_signing_key();
    sentinel_audit::save_keypair(&key, &args.key, &public)?;
    println!("wrote signing key:  {}", args.key.display());
    println!("wrote public key:   {}", public.display());
    println!("key id:             {}", sentinel_audit::key_id(&key.verifying_key()));
    println!("Share the public key with anyone who needs to verify audit logs.");
    Ok(())
}
