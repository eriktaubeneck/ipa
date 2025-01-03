use std::{convert::Infallible, marker::PhantomData};

use futures::{stream::iter, StreamExt, TryStreamExt};
use futures_util::stream::repeat;

use crate::{
    error::{Error, LengthError},
    ff::{
        boolean::Boolean,
        boolean_array::{BooleanArray, BA20, BA3, BA8},
        curve_points::RP25519,
        ec_prime_field::Fp25519,
        Field, Serializable, U128Conversions,
    },
    helpers::{
        query::{DpMechanism, IpaQueryConfig, QuerySize},
        BodyStream, LengthDelimitedStream, RecordsStream,
    },
    hpke::PrivateKeyRegistry,
    protocol::{
        basics::{BooleanArrayMul, Reveal, ShareKnownValue},
        context::{DZKPUpgraded, MacUpgraded, UpgradableContext},
        ipa_prf::{
            oprf_ipa, oprf_padding::PaddingParameters, prf_eval::PrfSharing, OPRFIPAInputRow,
            Shuffle, AGG_CHUNK, CONV_CHUNK, PRF_CHUNK, SORT_CHUNK,
        },
        prss::FromPrss,
        step::ProtocolStep::IpaPrf,
        BooleanProtocols,
    },
    report::{EncryptedOprfReport, EventType},
    secret_sharing::{
        replicated::semi_honest::{AdditiveShare as Replicated, AdditiveShare},
        BitDecomposed, SharedValue, TransposeFrom, Vectorizable,
    },
    sync::Arc,
};

pub struct OprfIpaQuery<C, HV, R: PrivateKeyRegistry> {
    config: IpaQueryConfig,
    key_registry: Arc<R>,
    phantom_data: PhantomData<(C, HV)>,
}

impl<C, HV, R: PrivateKeyRegistry> OprfIpaQuery<C, HV, R> {
    pub fn new(config: IpaQueryConfig, key_registry: Arc<R>) -> Self {
        Self {
            config,
            key_registry,
            phantom_data: PhantomData,
        }
    }
}

#[allow(clippy::too_many_lines)]
impl<C, HV, R> OprfIpaQuery<C, HV, R>
where
    C: UpgradableContext + Shuffle,
    HV: BooleanArray + U128Conversions,
    R: PrivateKeyRegistry,
    Replicated<Boolean>: Serializable + ShareKnownValue<C, Boolean>,
    Replicated<Boolean>: BooleanProtocols<DZKPUpgraded<C>>,
    Replicated<Boolean, 256>: BooleanProtocols<DZKPUpgraded<C>, 256>,
    Replicated<Boolean, AGG_CHUNK>: BooleanProtocols<DZKPUpgraded<C>, AGG_CHUNK>,
    Replicated<Boolean, CONV_CHUNK>: BooleanProtocols<DZKPUpgraded<C>, CONV_CHUNK>,
    Replicated<Boolean, SORT_CHUNK>: BooleanProtocols<DZKPUpgraded<C>, SORT_CHUNK>,
    Replicated<Fp25519, PRF_CHUNK>:
        PrfSharing<MacUpgraded<C, Fp25519>, PRF_CHUNK, Field = Fp25519> + FromPrss,
    Replicated<RP25519, PRF_CHUNK>:
        Reveal<MacUpgraded<C, Fp25519>, Output = <RP25519 as Vectorizable<PRF_CHUNK>>::Array>,
    Replicated<BA8>: BooleanArrayMul<DZKPUpgraded<C>>
        + Reveal<DZKPUpgraded<C>, Output = <BA8 as Vectorizable<1>>::Array>,
    Replicated<BA20>: BooleanArrayMul<DZKPUpgraded<C>>,
    Replicated<BA3>: BooleanArrayMul<DZKPUpgraded<C>>,
    Vec<Replicated<HV>>:
        for<'a> TransposeFrom<&'a BitDecomposed<Replicated<Boolean, 256>>, Error = LengthError>,
    BitDecomposed<AdditiveShare<Boolean, 256>>:
        for<'a> TransposeFrom<&'a [AdditiveShare<HV>; 256], Error = Infallible>,
{
    #[tracing::instrument("oprf_ipa_query", skip_all, fields(sz=%query_size))]
    pub async fn execute(
        self,
        ctx: C,
        query_size: QuerySize,
        input_stream: BodyStream,
    ) -> Result<Vec<Replicated<HV>>, Error> {
        let Self {
            config,
            key_registry,
            phantom_data: _,
        } = self;
        tracing::info!("New query: {config:?}");
        let ctx = ctx.narrow(&IpaPrf);
        let sz = usize::from(query_size);

        let input = if config.plaintext_match_keys {
            let mut v = RecordsStream::<OPRFIPAInputRow<BA8, BA3, BA20>, _>::new(input_stream)
                .try_concat()
                .await?;
            v.truncate(sz);
            v
        } else {
            LengthDelimitedStream::<EncryptedOprfReport<BA8, BA3, BA20, _>, _>::new(input_stream)
                .map_err(Into::<Error>::into)
                .map_ok(|enc_reports| {
                    iter(enc_reports.into_iter().map(|enc_report| {
                        enc_report
                            .decrypt(key_registry.as_ref())
                            .map_err(Into::<Error>::into)
                    }))
                })
                .try_flatten()
                .take(sz)
                .zip(repeat(ctx.clone()))
                .map(|(res, ctx)| {
                    res.map(|report| {
                        let is_trigger = Replicated::<Boolean>::share_known_value(
                            &ctx,
                            match report.event_type {
                                EventType::Source => Boolean::ZERO,
                                EventType::Trigger => Boolean::ONE,
                            },
                        );

                        OPRFIPAInputRow {
                            timestamp: report.timestamp,
                            match_key: report.match_key,
                            is_trigger,
                            breakdown_key: report.breakdown_key,
                            trigger_value: report.trigger_value,
                        }
                    })
                })
                .try_collect::<Vec<_>>()
                .await?
        };

        let aws = config.attribution_window_seconds;
        let dp_params: DpMechanism = match config.with_dp {
            0 => DpMechanism::NoDp,
            _ => DpMechanism::DiscreteLaplace {
                epsilon: config.epsilon,
            },
        };

        #[cfg(feature = "relaxed-dp")]
        let padding_params = PaddingParameters::relaxed();
        #[cfg(not(feature = "relaxed-dp"))]
        let padding_params = PaddingParameters::default();
        match config.per_user_credit_cap {
            1 => oprf_ipa::<_, BA8, BA3, HV, BA20, 1, 256>(ctx, input, aws, dp_params, padding_params).await,
            2 | 4 => oprf_ipa::<_, BA8, BA3, HV, BA20, 2, 256>(ctx, input, aws, dp_params, padding_params).await,
            8 => oprf_ipa::<_, BA8, BA3, HV, BA20, 3, 256>(ctx, input, aws, dp_params, padding_params).await,
            16 => oprf_ipa::<_, BA8, BA3, HV, BA20, 4, 256>(ctx, input, aws, dp_params, padding_params).await,
            32 => oprf_ipa::<_, BA8, BA3, HV, BA20, 5, 256>(ctx, input, aws, dp_params, padding_params).await,
            64 => oprf_ipa::<_, BA8, BA3, HV, BA20, 6, 256>(ctx, input, aws, dp_params, padding_params).await,
            128 => oprf_ipa::<_, BA8, BA3, HV, BA20, 7, 256>(ctx, input, aws, dp_params, padding_params).await,
            _ => panic!(
                "Invalid value specified for per-user cap: {:?}. Must be one of 1, 2, 4, 8, 16, 32, 64, or 128.",
                config.per_user_credit_cap
            ),
        }
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::{iter::zip, sync::Arc};

    use rand::rngs::StdRng;
    use rand_core::SeedableRng;

    use crate::{
        ff::{
            boolean_array::{BA16, BA20, BA3, BA8},
            U128Conversions,
        },
        helpers::{
            query::{IpaQueryConfig, QuerySize},
            BodyStream,
        },
        hpke::{KeyPair, KeyRegistry},
        query::runner::OprfIpaQuery,
        report::{OprfReport, DEFAULT_KEY_ID},
        secret_sharing::IntoShares,
        test_fixture::{ipa::TestRawDataRecord, join3v, Reconstruct, TestWorld},
    };

    #[tokio::test]
    async fn encrypted_reports() {
        const EXPECTED: &[u128] = &[0, 8, 5];

        let records: Vec<TestRawDataRecord> = vec![
            TestRawDataRecord {
                timestamp: 0,
                user_id: 12345,
                is_trigger_report: false,
                breakdown_key: 2,
                trigger_value: 0,
            },
            TestRawDataRecord {
                timestamp: 4,
                user_id: 68362,
                is_trigger_report: false,
                breakdown_key: 1,
                trigger_value: 0,
            },
            TestRawDataRecord {
                timestamp: 10,
                user_id: 12345,
                is_trigger_report: true,
                breakdown_key: 0,
                trigger_value: 5,
            },
            TestRawDataRecord {
                timestamp: 12,
                user_id: 68362,
                is_trigger_report: true,
                breakdown_key: 0,
                trigger_value: 2,
            },
            TestRawDataRecord {
                timestamp: 20,
                user_id: 68362,
                is_trigger_report: false,
                breakdown_key: 1,
                trigger_value: 0,
            },
            TestRawDataRecord {
                timestamp: 30,
                user_id: 68362,
                is_trigger_report: true,
                breakdown_key: 1,
                trigger_value: 7,
            },
        ];

        let query_size = QuerySize::try_from(records.len()).unwrap();

        let mut rng = StdRng::seed_from_u64(42);
        let key_id = DEFAULT_KEY_ID;
        let key_registry = Arc::new(KeyRegistry::<KeyPair>::random(1, &mut rng));

        let mut buffers: [_; 3] = std::array::from_fn(|_| Vec::new());

        let shares: [Vec<OprfReport<BA8, BA3, BA20>>; 3] = records.into_iter().share();
        for (buf, shares) in zip(&mut buffers, shares) {
            for share in shares {
                share
                    .delimited_encrypt_to(key_id, key_registry.as_ref(), &mut rng, buf)
                    .unwrap();
            }
        }

        let world = TestWorld::default();
        let contexts = world.contexts();
        #[allow(clippy::large_futures)]
        let results = join3v(buffers.into_iter().zip(contexts).map(|(buffer, ctx)| {
            let query_config = IpaQueryConfig {
                per_user_credit_cap: 8,
                attribution_window_seconds: None,
                max_breakdown_key: 3,
                with_dp: 0,
                epsilon: 5.0,
                plaintext_match_keys: false,
            };
            let input = BodyStream::from(buffer);

            OprfIpaQuery::<_, BA16, KeyRegistry<KeyPair>>::new(
                query_config,
                Arc::clone(&key_registry),
            )
            .execute(ctx, query_size, input)
        }))
        .await;

        assert_eq!(
            results.reconstruct()[0..3]
                .iter()
                .map(U128Conversions::as_u128)
                .collect::<Vec<u128>>(),
            EXPECTED
        );
    }
}
