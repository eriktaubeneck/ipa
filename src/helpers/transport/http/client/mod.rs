mod error;

pub use error::Error;

use crate::{
    helpers::{
        query::{PrepareQuery, QueryConfig, QueryInput},
        transport::{
            self,
            http::{discovery::peer, CreateQueryResp, OriginHeader, PrepareQueryBody, StepHeaders},
        },
        HelperIdentity,
    },
    protocol::{QueryId, Step},
};
use axum::{
    body::{Bytes, StreamBody},
    http::{
        uri::{self, PathAndQuery},
        Request,
    },
};
use futures::Stream;
use hyper::{body, client::HttpConnector, Body, Client, Response, Uri};
use hyper_tls::HttpsConnector;
use std::collections::HashMap;
use std::pin::Pin;

pub struct HttpSendMessagesArgs<'a> {
    pub query_id: QueryId,
    pub step: &'a Step,
    pub offset: u32,
    pub messages: Bytes,
}

#[allow(clippy::type_complexity)] // TODO: maybe alias a type for the `dyn Stream`
#[derive(Debug, Clone)]
pub struct MpcHelperClient {
    client: Client<HttpsConnector<HttpConnector>, Body>,
    streaming_client: Client<
        HttpsConnector<HttpConnector>,
        StreamBody<Pin<Box<dyn Stream<Item = Result<Vec<u8>, transport::Error>> + Send>>>,
    >,
    scheme: uri::Scheme,
    authority: uri::Authority,
}

impl MpcHelperClient {
    #[must_use]
    pub fn from_conf(
        peers_conf: &'static HashMap<HelperIdentity, peer::Config>,
    ) -> HashMap<HelperIdentity, MpcHelperClient> {
        let mut clients = HashMap::with_capacity(peers_conf.len());
        for (id, conf) in peers_conf {
            clients.insert(id.clone(), Self::new(conf.origin.clone()));
        }
        clients
    }

    /// addr must have a valid scheme and authority
    /// # Panics
    /// if addr does not have scheme and authority
    #[must_use]
    pub fn new(addr: Uri) -> Self {
        // this works for both http and https
        let https = HttpsConnector::new();
        let client = Client::builder().build(https.clone());
        let streaming_client = Client::builder().build(https);
        let parts = addr.into_parts();
        Self {
            client,
            streaming_client,
            scheme: parts.scheme.unwrap(),
            authority: parts.authority.unwrap(),
        }
    }

    /// same as new, but first parses the addr from a [&str]
    /// # Errors
    /// if addr is an invalid [Uri], this will fail
    pub fn with_str_addr(addr: &str) -> Result<Self, Error> {
        Ok(Self::new(addr.parse()?))
    }

    fn build_uri<T>(&self, p_and_q: T) -> Result<Uri, Error>
    where
        PathAndQuery: TryFrom<T>,
        <PathAndQuery as TryFrom<T>>::Error: Into<axum::http::Error>,
    {
        Ok(uri::Builder::new()
            .scheme(self.scheme.clone())
            .authority(self.authority.clone())
            .path_and_query(p_and_q)
            .build()?)
    }

    /// Responds with whatever input is passed to it
    /// # Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    pub async fn echo(&self, s: &str) -> Result<Vec<u8>, Error> {
        let uri = self.build_uri(format!("/echo?foo={s}"))?;

        let response = self.client.get(uri).await?;
        let result = hyper::body::to_bytes(response.into_body()).await?;
        Ok(result.to_vec())
    }

    async fn resp_ok(resp: Response<Body>) -> Result<(), Error> {
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(Error::from_failed_resp(resp).await)
        }
    }

    pub async fn create_query(&self, data: QueryConfig) -> Result<QueryId, Error> {
        let uri = self.build_uri(format!(
            "/query?field_type={}&query_type={}",
            data.field_type.as_ref(),
            data.query_type.as_ref()
        ))?;
        let req = Request::post(uri).body(Body::empty())?;
        let resp = self.client.request(req).await?;
        if resp.status().is_success() {
            let body_bytes = body::to_bytes(resp.into_body()).await?;
            let CreateQueryResp { query_id } = serde_json::from_slice(&body_bytes)?;
            Ok(query_id)
        } else {
            Err(Error::from_failed_resp(resp).await)
        }
    }

    /// Wait for completion of the query and pull the results of this query. This is a blocking
    /// API so it is not supposed to be used outside of CLI context.
    ///
    /// ## Errors
    /// If there is any problem with communicating with the helper server
    #[cfg(feature = "cli")]
    pub async fn query_results(&self, query_id: QueryId) -> Result<Bytes, Error> {
        let uri = self.build_uri(format!("/query/{}/complete/", query_id.as_ref()))?;

        let req = Request::get(uri).body(Body::empty())?;

        let resp = self.client.request(req).await?;
        if resp.status().is_success() {
            Ok(body::to_bytes(resp.into_body()).await.unwrap())
        } else {
            Err(Error::from_failed_resp(resp).await)
        }
    }

    /// TODO: we need a client that can be used by any system that is not aware of the internals
    /// of the helper network. That means that create query and send inputs API need to be separated
    /// from prepare/step data etc.
    pub async fn prepare_query(
        &self,
        origin: &HelperIdentity,
        data: PrepareQuery,
    ) -> Result<(), Error> {
        let uri = self.build_uri(format!(
            "/query/{}?field_type={}&query_type={}",
            data.query_id.as_ref(),
            data.config.field_type.as_ref(),
            data.config.query_type.as_ref(),
        ))?;
        let origin_header = OriginHeader {
            origin: origin.clone(),
        };
        let body = PrepareQueryBody { roles: data.roles };
        let body = Body::from(serde_json::to_string(&body)?);
        let req = origin_header.add_to(Request::post(uri)).body(body)?;
        let resp = self.client.request(req).await?;
        Self::resp_ok(resp).await
    }

    pub async fn query_input(&self, data: QueryInput) -> Result<(), Error> {
        let uri = self.build_uri(format!(
            "/query/{}/input?field_type={}",
            data.query_id.as_ref(),
            data.field_type.as_ref()
        ))?;
        let body = StreamBody::new(data.input_stream);
        let req = Request::post(uri).body(body)?;
        let resp = self.streaming_client.request(req).await?;
        Self::resp_ok(resp).await
    }

    /// Sends a batch of messages associated with a query's step to another helper. Messages are a
    /// contiguous block of records. Also includes [`crate::protocol::RecordId`] information and
    /// [`crate::helpers::network::ChannelId`].
    /// # Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    /// # Panics
    /// If messages size > max u32 (unlikely)
    pub async fn step(
        &self,
        origin: &HelperIdentity,
        query_id: QueryId,
        step: Step,
        payload: Vec<u8>,
        offset: u32,
    ) -> Result<(), Error> {
        let uri = self.build_uri(format!(
            "/query/{}/step/{}",
            query_id.as_ref(),
            step.as_ref(),
        ))?;
        let headers = StepHeaders { offset };
        let origin_header = OriginHeader {
            origin: origin.clone(),
        };

        let body = Body::from(payload);
        let req = Request::post(uri);
        let req = headers.add_to(origin_header.add_to(req));
        let req = req.body(body)?;
        let resp = self.client.request(req).await?;
        Self::resp_ok(resp).await
    }
}
