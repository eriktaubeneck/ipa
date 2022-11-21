use async_trait::async_trait;
use futures::{future::join_all, Future};
use rand::{distributions::Standard, prelude::Distribution};

use crate::{
    ff::Field,
    helpers::{
        messaging::{Gateway, GatewayConfig},
        SendBufferConfig,
    },
    protocol::{context::SemiHonestProtocolContext, prss::Endpoint as PrssEndpoint, QueryId},
    test_fixture::{
        logging, make_contexts, make_participants, network::InMemoryNetwork, sharing::IntoShares,
    },
};
use std::{fmt::Debug, iter::zip, sync::Arc};

/// Test environment for protocols to run tests that require communication between helpers.
/// For now the messages sent through it never leave the test infra memory perimeter, so
/// there is no need to associate each of them with `QueryId`, but this API makes it possible
/// to do if we need it.
#[derive(Debug)]
pub struct TestWorld {
    pub query_id: QueryId,
    pub gateways: [Gateway; 3],
    pub participants: [PrssEndpoint; 3],
    _network: Arc<InMemoryNetwork>,
}

#[derive(Copy, Clone)]
pub struct TestWorldConfig {
    pub gateway_config: GatewayConfig,
}

impl Default for TestWorldConfig {
    fn default() -> Self {
        Self {
            gateway_config: GatewayConfig {
                send_buffer_config: SendBufferConfig {
                    /// This value set to 1 effectively means no buffering. This is the desired mode
                    /// for unit tests to drive them to completion as fast as possible.
                    items_in_batch: 1,

                    /// How many messages can be sent in parallel. This value is picked arbitrarily as
                    /// most unit tests don't send more than this value, so the setup does not have to
                    /// be annoying. `items_in_batch` * `batch_count` defines the total capacity for
                    /// send buffer. Increasing this value does not really impact the latency for tests
                    /// because they flush the data to network once they've accumulated at least
                    /// `items_in_batch` elements. Ofc setting it to some absurdly large value is going
                    /// to be problematic from memory perspective.
                    batch_count: 40,
                },
            },
        }
    }
}

/// Creates a new `TestWorld` instance using the provided `config`.
#[must_use]
#[allow(clippy::missing_panics_doc)]
pub fn make_with_config(query_id: QueryId, config: TestWorldConfig) -> TestWorld {
    logging::setup();

    let participants = make_participants();
    let network = InMemoryNetwork::new();
    let gateways = network
        .endpoints
        .iter()
        .map(|endpoint| Gateway::new(endpoint.role, endpoint, config.gateway_config))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    TestWorld {
        query_id,
        gateways,
        participants,
        _network: network,
    }
}

/// Creates a new `TestWorld` instance.
#[must_use]
#[allow(clippy::missing_panics_doc)]
pub fn make(query_id: QueryId) -> TestWorld {
    let config = TestWorldConfig::default();
    make_with_config(query_id, config)
}

#[async_trait]
pub trait Runner<I, A> {
    async fn semi_honest<'a, F, O, H, X>(&'a self, input: I, helper_fn: H) -> [O; 3]
    where
        F: Field,
        O: Send + Debug,
        H: FnMut(SemiHonestProtocolContext<'a, F>, A) -> X + Send,
        X: Future<Output = O> + Send,
        Standard: Distribution<F>;
}

#[async_trait]
impl<I, A> Runner<I, A> for TestWorld
where
    I: 'static + IntoShares<A> + Send,
    A: Send,
{
    async fn semi_honest<'a, F, O, H, X>(&'a self, input: I, mut helper_fn: H) -> [O; 3]
    where
        F: Field,
        O: Send + Debug,
        H: FnMut(SemiHonestProtocolContext<'a, F>, A) -> X + Send,
        X: Future<Output = O> + Send,
        Standard: Distribution<F>,
    {
        let contexts = make_contexts::<F>(self);
        let input_shares = input.share();

        let output =
            join_all(zip(contexts, input_shares).map(|(ctx, shares)| helper_fn(ctx, shares))).await;
        <[_; 3]>::try_from(output).unwrap()
    }
}
