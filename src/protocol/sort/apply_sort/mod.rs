pub mod shuffle;

pub use shuffle::{shuffle_shares, Resharable};

use crate::{
    error::Error,
    ff::Field,
    protocol::{
        context::Context,
        sort::{
            apply::apply_inv, generate_permutation::RevealedAndRandomPermutations,
            ApplyInvStep::ShuffleInputs,
        },
    },
    secret_sharing::SecretSharing,
};

/// # Errors
/// Propagates errors from shuffle/reshare
pub async fn apply_sort_permutation<C, F, S, I>(
    ctx: C,
    input: Vec<I>,
    sort_permutation: &RevealedAndRandomPermutations,
) -> Result<Vec<I>, Error>
where
    C: Context<F, Share = S>,
    F: Field,
    S: SecretSharing<F>,
    I: Resharable<F, Share = S> + Send + Sync,
{
    let mut shuffled_objects = shuffle_shares(
        input,
        (
            &sort_permutation.randoms_for_shuffle.0,
            &sort_permutation.randoms_for_shuffle.1,
        ),
        ctx.narrow(&ShuffleInputs),
    )
    .await?;

    apply_inv(&sort_permutation.revealed, &mut shuffled_objects);
    Ok(shuffled_objects)
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::{
        bits::BitArray,
        ff::Fp32BitPrime,
        protocol::{
            attribution::{accumulate_credit::input::AttributionTestInput, AttributionInputRow},
            context::Context,
            modulus_conversion::{convert_all_bits, convert_all_bits_local},
            sort::{
                apply_sort::apply_sort_permutation,
                generate_permutation::generate_permutation_and_reveal_shuffled,
            },
            IpaProtocolStep::SortPreAccumulation,
        },
        rand::{thread_rng, Rng},
        secret_sharing::SharedValue,
        test_fixture::{MaskedMatchKey, Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn semi_honest() {
        const COUNT: usize = 5;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::new().await;
        let mut rng = thread_rng();

        let mut match_keys = Vec::with_capacity(COUNT);
        match_keys.resize_with(COUNT, || rng.gen::<MaskedMatchKey>());

        let permutation =
            permutation::sort(match_keys.iter().map(|mk| mk.as_u128()).collect::<Vec<_>>());

        let mut sidecar: Vec<AttributionTestInput<Fp32BitPrime>> = Vec::with_capacity(COUNT);
        sidecar.resize_with(COUNT, || {
            AttributionTestInput([(); 4].map(|_| rng.gen::<Fp32BitPrime>()))
        });
        let expected = permutation.apply_slice(&sidecar);

        let result: [Vec<AttributionInputRow<Fp32BitPrime>>; 3] = world
            .semi_honest(
                (match_keys, sidecar),
                |ctx, (mk_shares, secret)| async move {
                    let local_lists = convert_all_bits_local(ctx.role(), &mk_shares);
                    let converted_shares =
                        convert_all_bits(&ctx.narrow("convert_all_bits"), &local_lists)
                            .await
                            .unwrap();
                    let sort_permutation = generate_permutation_and_reveal_shuffled(
                        ctx.narrow(&SortPreAccumulation),
                        &converted_shares,
                        MaskedMatchKey::BITS,
                        NUM_MULTI_BITS,
                    )
                    .await
                    .unwrap();
                    apply_sort_permutation(ctx, secret, &sort_permutation)
                        .await
                        .unwrap()
                },
            )
            .await;
        assert_eq!(&expected[..], &result.reconstruct()[..]);
    }
}
