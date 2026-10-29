//! Dedicated evidence worker; run separately from Gail's serving budget.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    nm_workflow_core::runtime::serve(
        nm_workflow_core::App::from_env("verity").await?,
        verity::routes(),
    )
    .await?;
    Ok(())
}
