use futures::compat::Future01CompatExt;

pub async fn async_reqwest_to_error(request: reqwest::r#async::RequestBuilder) -> failure::Fallible<reqwest::r#async::Response> {
    let c = request.send().compat().await?;
    Ok(c.error_for_status()?)
}