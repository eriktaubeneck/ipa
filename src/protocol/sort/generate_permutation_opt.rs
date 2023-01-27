use crate::{
    error::Error,
    ff::Field,
    protocol::{
        context::{Context, SemiHonestContext},
        sort::{
            compose::compose,
            generate_permutation::shuffle_and_reveal_permutation,
            multi_bit_permutation::multi_bit_permutation,
            secureapplyinv::secureapplyinv,
            SortStep::{BitPermutationStep, ComposeStep, MultiApplyInv, ShuffleRevealPermutation},
        },
        IpaProtocolStep::Sort,
    },
    secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
};
use futures::future::try_join_all;
use std::iter::repeat;

/// This is an implementation of `OptGenPerm` (Algorithm 12) described in:
/// "An Efficient Secure Three-Party Sorting Protocol with an Honest Majority"
/// by K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, N. Kiribuchi, and B. Pinkas
/// <https://eprint.iacr.org/2019/695.pdf>.
/// This protocol generates optimized permutation of a stable sort for the given shares of inputs.
///
/// Steps
/// For the `num_multi_bits`
/// 1. Get replicated shares in Field using modulus conversion
/// 2. Compute bit permutation that sorts 0..`num_multi_bits`
/// For `num_multi_bits` to N-1th bit of input share
/// 1. Shuffle and reveal the i-1th composition
/// 2. Get replicated shares in Field using modulus conversion
/// 3. Sort i..i+`num_multi_bits` bits based on i-1th bits by applying i-1th composition on all these bits
/// 4  Compute bit permutation that sorts i..i+`num_multi_bits`
/// 5. Compute ith composition by composing i-1th composition on ith permutation
/// In the end, n-1th composition is returned. This is the permutation which sorts the inputs
///
/// # Errors
/// If any underlying protocol fails
/// # Panics
/// Panics if input doesn't have same number of bits as `num_bits`
pub async fn generate_permutation_opt<F>(
    ctx: SemiHonestContext<'_, F>,
    sort_keys: &[Vec<Replicated<F>>],
    num_bits: u32,
    num_multi_bits: u32,
) -> Result<Vec<Replicated<F>>, Error>
where
    F: Field,
{
    let ctx_0 = ctx.narrow(&Sort(0));
    assert_eq!(sort_keys.len(), num_bits as usize);

    let last_bit_num = std::cmp::min(num_multi_bits, num_bits);

    let lsb_permutation = multi_bit_permutation(
        ctx_0.narrow(&BitPermutationStep),
        &sort_keys[0..last_bit_num.try_into().unwrap()],
    )
    .await?;

    let input_len = u32::try_from(sort_keys[0].len()).unwrap(); // safe, we don't sort more that 1B rows

    let mut composed_less_significant_bits_permutation = lsb_permutation;
    for bit_num in (num_multi_bits..num_bits).step_by(num_multi_bits.try_into().unwrap()) {
        let ctx_bit = ctx.narrow(&Sort(bit_num));
        let revealed_and_random_permutations = shuffle_and_reveal_permutation(
            ctx_bit.narrow(&ShuffleRevealPermutation),
            input_len,
            composed_less_significant_bits_permutation,
        )
        .await?;

        let (randoms_for_shuffle0, randoms_for_shuffle1, revealed) = (
            revealed_and_random_permutations
                .randoms_for_shuffle
                .0
                .as_slice(),
            revealed_and_random_permutations
                .randoms_for_shuffle
                .1
                .as_slice(),
            revealed_and_random_permutations.revealed.as_slice(),
        );

        let last_bit_num = std::cmp::min(bit_num + num_multi_bits, num_bits);

        let futures =
            (bit_num..last_bit_num)
                .zip(repeat(ctx_bit.clone()))
                .map(|(idx, ctx_bit)| async move {
                    secureapplyinv(
                        ctx_bit.narrow(&MultiApplyInv(idx)),
                        sort_keys[idx as usize].clone(),
                        (randoms_for_shuffle0, randoms_for_shuffle1),
                        revealed,
                    )
                    .await
                });
        let next_few_bits_sorted_by_less_significant_bits = try_join_all(futures).await?;

        let next_few_bits_permutation = multi_bit_permutation(
            ctx_bit.narrow(&BitPermutationStep),
            &next_few_bits_sorted_by_less_significant_bits,
        )
        .await?;

        composed_less_significant_bits_permutation = compose(
            ctx_bit.narrow(&ComposeStep),
            (
                revealed_and_random_permutations
                    .randoms_for_shuffle
                    .0
                    .as_slice(),
                revealed_and_random_permutations
                    .randoms_for_shuffle
                    .1
                    .as_slice(),
            ),
            &revealed_and_random_permutations.revealed,
            next_few_bits_permutation,
        )
        .await?;
    }
    Ok(composed_less_significant_bits_permutation)
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::{
        bits::BitArray,
        ff::{Field, Fp31},
        protocol::{
            context::{Context, SemiHonestContext},
            modulus_conversion::{convert_all_bits, convert_all_bits_local},
            sort::generate_permutation_opt::generate_permutation_opt,
        },
        rand::{thread_rng, Rng},
        secret_sharing::SharedValue,
        test_fixture::{MaskedMatchKey, Reconstruct, Runner, TestWorld},
    };
    use std::iter::zip;

    #[tokio::test]
    pub async fn semi_honest() {
        const COUNT: usize = 10;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::new().await;
        let mut rng = thread_rng();

        let mut match_keys = Vec::with_capacity(COUNT);
        match_keys.resize_with(COUNT, || rng.gen::<MaskedMatchKey>());

        let mut expected = match_keys.iter().map(|mk| mk.as_u128()).collect::<Vec<_>>();
        expected.sort_unstable();

        let result = world
            .semi_honest(
                match_keys.clone(),
                |ctx: SemiHonestContext<Fp31>, mk_shares| async move {
                    let local_lists = convert_all_bits_local(ctx.role(), &mk_shares);
                    let converted_shares = convert_all_bits(&ctx, &local_lists).await.unwrap();
                    generate_permutation_opt(
                        ctx.narrow("sort"),
                        &converted_shares,
                        MaskedMatchKey::BITS,
                        NUM_MULTI_BITS,
                    )
                    .await
                    .unwrap()
                },
            )
            .await;

        let mut mpc_sorted_list = (0..u128::try_from(COUNT).unwrap()).collect::<Vec<_>>();
        for (match_key, index) in zip(match_keys, result.reconstruct()) {
            mpc_sorted_list[index.as_u128() as usize] = match_key.as_u128();
        }

        assert_eq!(expected, mpc_sorted_list);
    }
}
