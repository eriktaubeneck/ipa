use crate::{
    error::Error,
    ff::Field,
    helpers::{Direction, Role},
    protocol::{
        context::{Context, MaliciousContext, SemiHonestContext},
        prss::SharedRandomness,
        sort::{
            apply_sort::shuffle::InnerVectorElementStep,
            ReshareStep::{RandomnessForValidation, ReshareRx},
        },
        NoRecord, RecordBinding, RecordId,
    },
    secret_sharing::replicated::{
        malicious::AdditiveShare as MaliciousReplicated, semi_honest::AdditiveShare as Replicated,
        ReplicatedSecretSharing,
    },
    seq_join::seq_try_join_all,
};
use async_trait::async_trait;
use embed_doc_image::embed_doc_image;
use futures::future::{try_join, try_join_all};
use std::iter::{repeat, zip};
#[embed_doc_image("reshare", "images/sort/reshare.png")]
/// Trait for reshare protocol to renew shares of a secret value for all 3 helpers.
///
/// Steps
/// ![Reshare steps][reshare]
/// 1. While calculating for a helper, we call pseudo random secret sharing (prss) to get random values which match
///    with those generated by other helpers (say `rand_left`, `rand_right`)
///    `to_helper.left` knows `rand_left` (named r1) and `to_helper.right` knows `rand_right` (named r0)
/// 2. `to_helper.left` calculates part1 = (a1 + a2) - r2 = Same as (input.left() + input.right()) - r1 from helper POV
///    `to_helper.right` calculates part2 = (a3 - r3) = Same as (input.left() - r0) from helper POV
/// 3. `to_helper.left` and `to_helper.right` exchange their calculated shares
/// 4. Everyone sets their shares
///    `to_helper.left`  = (part1 + part2, `rand_left`)  = (part1 + part2, r1)
///    `to_helper`       = (`rand_left`, `rand_right`)     = (r0, r1)
///    `to_helper.right` = (`rand_right`, part1 + part2) = (r0, part1 + part2)
#[async_trait]
pub trait Reshare<C: Context, B: RecordBinding>: Sized {
    async fn reshare<'fut>(
        &self,
        ctx: C,
        record_binding: B,
        to_helper: Role,
    ) -> Result<Self, Error>
    where
        C: 'fut;
}

// Variant of Reshare implemented for types like [T] where resharing doesn't return `Self`.  This is
// just a more general version of `Reshare`, but a bunch of consumers that don't otherwise care
// would need to specify an associated type bound `T: Reshare<Output = T>` to use this more general
// version.
#[async_trait]
pub trait ReshareBorrowed<C: Context, B: RecordBinding> {
    type Output: Sized;
    async fn reshare_borrowed<'fut>(
        &self,
        ctx: C,
        record_binding: B,
        to_helper: Role,
    ) -> Result<Self::Output, Error>
    where
        C: 'fut;
}

#[async_trait]
/// Reshare(i, \[x\])
/// This implements semi-honest reshare algorithm of "Efficient Secure Three-Party Sorting Protocol with an Honest Majority" at communication cost of 2R.
/// Input: Pi-1 and Pi+1 know their secret shares
/// Output: At the end of the protocol, all 3 helpers receive their shares of a new, random secret sharing of the secret value
impl<'a, F: Field> Reshare<SemiHonestContext<'a>, RecordId> for Replicated<F> {
    async fn reshare<'fut>(
        &self,
        ctx: SemiHonestContext<'a>,
        record_id: RecordId,
        to_helper: Role,
    ) -> Result<Self, Error>
    where
        SemiHonestContext<'a>: 'fut,
    {
        let r = ctx.prss().generate_fields(record_id);

        // `to_helper.left` calculates part1 = (self.0 + self.1) - r1 and sends part1 to `to_helper.right`
        // This is same as (a1 + a2) - r2 in the diagram
        if ctx.role() == to_helper.peer(Direction::Left) {
            let part1 = self.left() + self.right() - r.1;
            ctx.send_channel(to_helper.peer(Direction::Right))
                .send(record_id, part1)
                .await?;

            // Sleep until `to_helper.right` sends us their part2 value
            let part2 = ctx
                .recv_channel(to_helper.peer(Direction::Right))
                .receive(record_id)
                .await?;

            Ok(Replicated::new(part1 + part2, r.1))
        } else if ctx.role() == to_helper.peer(Direction::Right) {
            // `to_helper.right` calculates part2 = (self.left() - r0) and sends it to `to_helper.left`
            // This is same as (a3 - r3) in the diagram
            let part2 = self.left() - r.0;
            ctx.send_channel(to_helper.peer(Direction::Left))
                .send(record_id, part2)
                .await?;

            // Sleep until `to_helper.left` sends us their part1 value
            let part1: F = ctx
                .recv_channel(to_helper.peer(Direction::Left))
                .receive(record_id)
                .await?;

            Ok(Replicated::new(r.0, part1 + part2))
        } else {
            Ok(Replicated::new(r.0, r.1))
        }
    }
}

#[async_trait]
/// For malicious reshare, we run semi honest reshare protocol twice, once for x and another for rx and return the results
/// # Errors
/// If either of reshares fails
impl<'a, F: Field> Reshare<MaliciousContext<'a, F>, RecordId> for MaliciousReplicated<F> {
    async fn reshare<'fut>(
        &self,
        ctx: MaliciousContext<'a, F>,
        record_id: RecordId,
        to_helper: Role,
    ) -> Result<Self, Error>
    where
        MaliciousContext<'a, F>: 'fut,
    {
        use crate::{
            protocol::context::SpecialAccessToMaliciousContext,
            secret_sharing::replicated::malicious::ThisCodeIsAuthorizedToDowngradeFromMalicious,
        };
        let random_constant_ctx = ctx.narrow(&RandomnessForValidation);

        let (rx, x) = try_join(
            self.rx().reshare(
                ctx.narrow(&ReshareRx).semi_honest_context(),
                record_id,
                to_helper,
            ),
            self.x().access_without_downgrade().reshare(
                ctx.semi_honest_context(),
                record_id,
                to_helper,
            ),
        )
        .await?;
        let malicious_input = MaliciousReplicated::new(x, rx);
        random_constant_ctx.accumulate_macs(record_id, &malicious_input);
        Ok(malicious_input)
    }
}

// `T` must be `Send + Sync` because we are passing `&T` into futures. In practice `T` is plain old data,
// which is always `Sync`.
#[async_trait]
impl<T, C: Context> ReshareBorrowed<C, RecordId> for [T]
where
    T: Reshare<C, RecordId> + Send + Sync,
{
    type Output = Vec<T>;
    /// This is intended to be used for resharing bit-decomposed values, i.e., vectors with a
    /// finite, small maximum length.
    /// # Errors
    /// If the vector has more than 64 elements
    async fn reshare_borrowed<'fut>(
        self: &[T],
        ctx: C,
        record_id: RecordId,
        to_helper: Role,
    ) -> Result<Vec<T>, Error>
    where
        C: 'fut,
    {
        // This is a truly parallel operation, so no `seq_try_join_all`.
        try_join_all(self.iter().enumerate().map(|(i, x)| {
            let c = ctx.narrow(&InnerVectorElementStep::from(i));
            async move { x.reshare(c, record_id, to_helper).await }
        }))
        .await
    }
}

// T must be `Sync` because we are passing `&T` into futures. In practice `T` is plain old data,
// which is always `Sync`.
#[async_trait]
impl<T, C: Context> ReshareBorrowed<C, NoRecord> for [T]
where
    T: Reshare<C, RecordId> + Send + Sync,
{
    type Output = Vec<T>;
    /// This is intended to be used for resharing arbitrarily long vectors of something other than
    /// bit-decomposed values (because resharing of bit-decomposed values uses record iteration).
    async fn reshare_borrowed<'fut>(
        self: &[T],
        ctx: C,
        _: NoRecord,
        to_helper: Role,
    ) -> Result<Vec<T>, Error>
    where
        C: 'fut,
    {
        seq_try_join_all(
            zip(repeat(ctx.set_total_records(self.len())), self.iter())
                .enumerate()
                .map(|(i, (c, x))| async move { x.reshare(c, RecordId::from(i), to_helper).await }),
        )
        .await
    }
}

// Note that this can delegate to either of the ReshareBorrowed implementations (short or long
// vectors) depending on the specified RecordBinding.
#[async_trait]
impl<T, C: Context, B: RecordBinding> Reshare<C, B> for Vec<T>
where
    T: Reshare<C, RecordId> + Send + Sync,
    [T]: ReshareBorrowed<C, B, Output = Vec<T>>,
{
    async fn reshare<'fut>(
        self: &Vec<T>,
        ctx: C,
        record_binding: B,
        to_helper: Role,
    ) -> Result<Vec<T>, Error>
    where
        C: 'fut,
    {
        self.as_slice()
            .reshare_borrowed(ctx, record_binding, to_helper)
            .await
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    mod semi_honest {
        use crate::{
            ff::Fp32BitPrime,
            helpers::Role,
            protocol::{basics::Reshare, context::Context, prss::SharedRandomness, RecordId},
            rand::{thread_rng, Rng},
            test_fixture::{Reconstruct, Runner, TestWorld},
        };

        /// Validates that reshare protocol actually generates new additive shares using PRSS.
        #[tokio::test]
        async fn generates_unique_shares() {
            let world = TestWorld::default();

            for &target in Role::all() {
                let secret = thread_rng().gen::<Fp32BitPrime>();
                let shares = world
                    .semi_honest(secret, |ctx, share| async move {
                        let record_id = RecordId::from(0);
                        let ctx = ctx.set_total_records(1);

                        // run reshare protocol for all helpers except the one that does not know the input
                        if ctx.role() == target {
                            // test follows the reshare protocol
                            ctx.prss().generate_fields(record_id).into()
                        } else {
                            share.reshare(ctx, record_id, target).await.unwrap()
                        }
                    })
                    .await;

                let reshared_secret = shares.reconstruct();

                // if reshare cheated and just returned its input without adding randomness,
                // this test will catch it with the probability of error (1/|F|)^2.
                // Using 32 bit field is sufficient to consider error probability negligible
                assert_eq!(secret, reshared_secret);
            }
        }

        /// This test validates the correctness of the protocol, relying on `generates_unique_shares`
        /// to ensure security. It does not verify that helpers actually attempt to generate new shares
        /// so a naive implementation of reshare that just output shares `[O]` = `[I]` where `[I]` is
        /// the input will pass this test. However `generates_unique_shares` will fail this implementation.
        #[tokio::test]
        async fn correct() {
            let world = TestWorld::default();

            for &role in Role::all() {
                let secret = thread_rng().gen::<Fp32BitPrime>();
                let new_shares = world
                    .semi_honest(secret, |ctx, share| async move {
                        share
                            .reshare(ctx.set_total_records(1), RecordId::from(0), role)
                            .await
                            .unwrap()
                    })
                    .await;

                assert_eq!(secret, new_shares.reconstruct());
            }
        }
    }

    mod malicious {
        use futures::future::try_join;

        use crate::{
            error::Error,
            ff::{Field, Fp32BitPrime},
            helpers::{Direction, Role},
            protocol::{
                basics::Reshare,
                context::{Context, MaliciousContext, SemiHonestContext},
                malicious::MaliciousValidator,
                prss::SharedRandomness,
                sort::ReshareStep::{RandomnessForValidation, ReshareRx},
                RecordId,
            },
            rand::{thread_rng, Rng},
            secret_sharing::replicated::{
                malicious::AdditiveShare as MaliciousReplicated,
                semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing,
            },
            test_fixture::{Reconstruct, Runner, TestWorld},
        };

        /// Relies on semi-honest protocol tests that enforce reshare to communicate and produce
        /// new shares.
        /// TODO: It would be great to have a test to validate that helpers cannot cheat. In this
        /// setting we have 1 helper that does not know the input and if another one is malicious
        /// adversary, we are only left with one honest helper that knows the input and can validate
        /// it.
        #[tokio::test]
        async fn correct() {
            let world = TestWorld::default();

            for &role in Role::all() {
                let secret = thread_rng().gen::<Fp32BitPrime>();
                let new_shares = world
                    .malicious(secret, |ctx, share| async move {
                        share
                            .reshare(ctx.set_total_records(1), RecordId::from(0), role)
                            .await
                            .unwrap()
                    })
                    .await;

                assert_eq!(secret, new_shares.reconstruct());
            }
        }

        async fn reshare_with_additive_attack<F: Field>(
            ctx: SemiHonestContext<'_>,
            input: &Replicated<F>,
            record_id: RecordId,
            to_helper: Role,
            additive_error: F,
        ) -> Result<Replicated<F>, Error> {
            let (r0, r1) = ctx.prss().generate_fields(record_id);

            // `to_helper.left` calculates part1 = (input.0 + input.1) - r1 and sends part1 to `to_helper.right`
            // This is same as (a1 + a2) - r2 in the diagram
            if ctx.role() == to_helper.peer(Direction::Left) {
                let send_channel = ctx.send_channel(to_helper.peer(Direction::Right));
                let receive_channel = ctx.recv_channel(to_helper.peer(Direction::Right));

                let part1 = input.left() + input.right() - r1 + additive_error;
                send_channel.send(record_id, part1).await?;

                // Sleep until `to_helper.right` sends us their part2 value
                let part2 = receive_channel.receive(record_id).await?;

                Ok(Replicated::new(part1 + part2, r1))
            } else if ctx.role() == to_helper.peer(Direction::Right) {
                let send_channel = ctx.send_channel(to_helper.peer(Direction::Left));
                let receive_channel = ctx.recv_channel::<F>(to_helper.peer(Direction::Left));

                // `to_helper.right` calculates part2 = (input.left() - r0) and sends it to `to_helper.left`
                // This is same as (a3 - r3) in the diagram
                let part2 = input.left() - r0 + additive_error;
                send_channel.send(record_id, part2).await?;

                // Sleep until `to_helper.left` sends us their part1 value
                let part1 = receive_channel.receive(record_id).await?;

                Ok(Replicated::new(r0, part1 + part2))
            } else {
                Ok(Replicated::new(r0, r1))
            }
        }

        async fn reshare_malicious_with_additive_attack<F: Field>(
            ctx: MaliciousContext<'_, F>,
            input: &MaliciousReplicated<F>,
            record_id: RecordId,
            to_helper: Role,
            additive_error: F,
        ) -> Result<MaliciousReplicated<F>, Error> {
            use crate::{
                protocol::context::SpecialAccessToMaliciousContext,
                secret_sharing::replicated::malicious::ThisCodeIsAuthorizedToDowngradeFromMalicious,
            };
            let random_constant_ctx = ctx.narrow(&RandomnessForValidation);

            let (rx, x) = try_join(
                reshare_with_additive_attack(
                    ctx.narrow(&ReshareRx).semi_honest_context(),
                    input.rx(),
                    record_id,
                    to_helper,
                    additive_error,
                ),
                reshare_with_additive_attack(
                    ctx.semi_honest_context(),
                    input.x().access_without_downgrade(),
                    record_id,
                    to_helper,
                    additive_error,
                ),
            )
            .await?;
            let malicious_input = MaliciousReplicated::new(x, rx);

            random_constant_ctx.accumulate_macs(record_id, &malicious_input);
            Ok(malicious_input)
        }

        #[tokio::test]
        async fn malicious_validation_fail() {
            let world = TestWorld::default();
            let mut rng = thread_rng();

            let a = rng.gen::<Fp32BitPrime>();

            let to_helper = Role::H1;
            for malicious_actor in &[Role::H2, Role::H3] {
                world
                    .semi_honest(a, |ctx, a| async move {
                        let v = MaliciousValidator::new(ctx);
                        let m_ctx = v.context().set_total_records(1);
                        let record_id = RecordId::from(0);
                        let m_a = v.context().upgrade(a).await.unwrap();

                        let m_reshared_a = if m_ctx.role() == *malicious_actor {
                            // This role is spoiling the value.
                            reshare_malicious_with_additive_attack(
                                m_ctx,
                                &m_a,
                                record_id,
                                to_helper,
                                Fp32BitPrime::ONE,
                            )
                            .await
                            .unwrap()
                        } else {
                            m_a.reshare(m_ctx, record_id, to_helper).await.unwrap()
                        };
                        match v.validate(m_reshared_a).await {
                            Ok(result) => panic!("Got a result {result:?}"),
                            Err(err) => assert!(matches!(err, Error::MaliciousSecurityCheckFailed)),
                        }
                    })
                    .await;
            }
        }
    }
}
