pub async fn async_reqwest_to_error(request: reqwest::RequestBuilder) -> failure::Fallible<reqwest::Response> {
    let c = request.send().await?;
    Ok(c.error_for_status()?)
}