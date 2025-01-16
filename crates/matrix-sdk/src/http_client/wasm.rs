// Copyright 2023 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use bytes::Bytes;
use bytesize::ByteSize;
use eyeball::SharedObservable;
use ruma::api::{error::FromHttpResponseError, IncomingResponse, OutgoingRequest};
use std::fmt::Debug;
use std::time::Duration;

use super::{response_to_http_response, HttpClient, TransmissionProgress};
use crate::{config::RequestConfig, error::HttpError};

impl HttpClient {
    pub(super) async fn send_request<R>(
        &self,
        request: http::Request<Bytes>,
        _config: RequestConfig,
        _send_progress: SharedObservable<TransmissionProgress>,
    ) -> Result<R::IncomingResponse, HttpError>
    where
        R: OutgoingRequest + Debug,
        HttpError: From<FromHttpResponseError<R::EndpointError>>,
    {
        tracing::debug!("Sending request");

        let request = reqwest::Request::try_from(request)?;
        let response = response_to_http_response(self.inner.execute(request).await?).await?;

        let status_code = response.status();
        let response_size = ByteSize(response.body().len().try_into().unwrap_or(u64::MAX));
        tracing::Span::current()
            .record("status", status_code.as_u16())
            .record("response_size", response_size.to_string_as(true));

        Ok(R::IncomingResponse::try_from_http_response(response)?)
    }
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn send_request(
    client: &reqwest::Client,
    request: &http::Request<Bytes>,
    _timeout: Duration,
    send_progress: SharedObservable<TransmissionProgress>,
) -> Result<http::Response<Bytes>, HttpError> {
    use http::header::CONTENT_LENGTH;

    let request = clone_request(request);
    let content_length = request.body().len();

    // Update progress total once, as streaming isn't supported in WASM.
    if send_progress.subscriber_count() != 0 {
        send_progress.update(|p| p.total += content_length);
    }

    let req = {
        let mut req = reqwest::Request::try_from(request)?;

        // Set the Content-Length header manually if needed.
        req.headers_mut().insert(CONTENT_LENGTH, content_length.into());

        // Set the timeout for the request.
        // This is not supported by the `reqwest` crate in WASM???
        // *req.timeout_mut() = Some(timeout);

        req
    };

    // Execute the request.
    let response = client.execute(req).await?;

    // Update progress to 100% after response.
    if send_progress.subscriber_count() != 0 {
        send_progress.update(|p| p.current = content_length);
    }

    // Convert the response to `http::Response<Bytes>`.
    Ok(response_to_http_response(response).await?)
}

// Clones all request parts except the extensions which can't be cloned.
// See also https://github.com/hyperium/http/issues/395
fn clone_request(request: &http::Request<Bytes>) -> http::Request<Bytes> {
    let mut builder = http::Request::builder()
        .version(request.version())
        .method(request.method())
        .uri(request.uri());
    *builder.headers_mut().unwrap() = request.headers().clone();
    builder.body(request.body().clone()).unwrap()
}
