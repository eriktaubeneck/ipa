use std::{
    iter::{repeat, zip},
    marker::PhantomData,
};

use crate::{
    bits::BitArray,
    error::Error,
    ff::Field,
    helpers::Role,
    protocol::{
        attribution::{
            accumulate_credit::accumulate_credit, aggregate_credit::aggregate_credit,
            credit_capping::credit_capping,
        },
        context::Context,
        sort::apply_sort::apply_sort_permutation,
        RecordId,
    },
    secret_sharing::{
        replicated::malicious::AdditiveShare as MaliciousReplicated,
        replicated::semi_honest::{AdditiveShare as Replicated, XorShare as XorReplicated},
        Arithmetic,
    },
};

use async_trait::async_trait;
use futures::future::{try_join3, try_join_all};

use super::{
    attribution::input::{MCAccumulateCreditInputRow, MCAggregateCreditOutputRow},
    context::{MaliciousContext, SemiHonestContext},
    malicious::MaliciousValidator,
    sort::generate_permutation::{
        generate_permutation_and_reveal_shuffled,
        malicious_generate_permutation_and_reveal_shuffled,
    },
};
use super::{
    modulus_conversion::{combine_slices, convert_all_bits, convert_all_bits_local},
    sort::apply_sort::shuffle::Resharable,
    Substep,
};
use crate::protocol::boolean::bitwise_equal::bitwise_equal;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    ModulusConversionForMatchKeys,
    ModulusConversionForBreakdownKeys,
    GenSortPermutationFromMatchKeys,
    ApplySortPermutation,
    ComputeHelperBits,
    AccumulateCredit,
    PerformUserCapping,
    AggregateCredit,
    AfterConvertAllBits,
    IPAModulusConvertedInputRowUpgrade
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::ModulusConversionForMatchKeys => "mod_conv_match_key",
            Self::ModulusConversionForBreakdownKeys => "mod_conv_breakdown_key",
            Self::GenSortPermutationFromMatchKeys => "gen_sort_permutation_from_match_keys",
            Self::ApplySortPermutation => "apply_sort_permutation",
            Self::ComputeHelperBits => "compute_helper_bits",
            Self::AccumulateCredit => "accumulate_credit",
            Self::PerformUserCapping => "user_capping",
            Self::AggregateCredit => "aggregate_credit",
            Self::AfterConvertAllBits => "after_convert_all_bits",
            Self::IPAModulusConvertedInputRowUpgrade => "modulus_converted_input_row_upgrade"
        }
    }
}
pub enum IPAInputRowResharableStep {
    MatchKeyShares,
    TriggerBit,
    BreakdownKey,
    TriggerValue,
}

impl Substep for IPAInputRowResharableStep {}

impl AsRef<str> for IPAInputRowResharableStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::MatchKeyShares => "match_key_shares",
            Self::TriggerBit => "is_trigger_bit",
            Self::BreakdownKey => "breakdown_key",
            Self::TriggerValue => "trigger_value",
        }
    }
}

pub struct IPAInputRow<F: Field, MK: BitArray, BK: BitArray> {
    pub mk_shares: XorReplicated<MK>,
    pub is_trigger_bit: Replicated<F>,
    pub breakdown_key: XorReplicated<BK>,
    pub trigger_value: Replicated<F>,
}

struct IPAModulusConvertedInputRow<F: Field, T: Arithmetic<F>> {
    mk_shares: Vec<T>,
    is_trigger_bit: T,
    breakdown_key: Vec<T>,
    trigger_value: T,
    _marker: PhantomData<F>,
}

#[async_trait]
impl<F: Field + Sized, T: Arithmetic<F>> Resharable<F> for IPAModulusConvertedInputRow<F, T> {
    type Share = T;

    async fn reshare<C>(&self, ctx: C, record_id: RecordId, to_helper: Role) -> Result<Self, Error>
    where
        C: Context<F, Share = <Self as Resharable<F>>::Share> + Send,
    {
        let f_mk_shares = self.mk_shares.reshare(
            ctx.narrow(&IPAInputRowResharableStep::MatchKeyShares),
            record_id,
            to_helper,
        );
        let f_is_trigger_bit = ctx.narrow(&IPAInputRowResharableStep::TriggerBit).reshare(
            &self.is_trigger_bit,
            record_id,
            to_helper,
        );
        let f_breakdown_key = self.breakdown_key.reshare(
            ctx.narrow(&IPAInputRowResharableStep::BreakdownKey),
            record_id,
            to_helper,
        );
        let f_trigger_value = ctx
            .narrow(&IPAInputRowResharableStep::TriggerValue)
            .reshare(&self.trigger_value, record_id, to_helper);

        let (mk_shares, breakdown_key, mut outputs) = try_join3(
            f_mk_shares,
            f_breakdown_key,
            try_join_all([f_is_trigger_bit, f_trigger_value]),
        )
        .await?;

        Ok(IPAModulusConvertedInputRow {
            mk_shares,
            breakdown_key,
            is_trigger_bit: outputs.remove(0),
            trigger_value: outputs.remove(0),
            _marker: PhantomData::default(),
        })
    }
}

impl<F: Field, T: Arithmetic<F>> IPAModulusConvertedInputRow<F, T> {
    #[allow(dead_code)]
    async fn upgrade_to_malicious(
        m_ctx: MaliciousContext<'_, F>,
        mk_shares: Vec<Replicated<F>>,
        is_trigger_bit: Replicated<F>,
        trigger_value: Replicated<F>,
        bk_shares: Vec<MaliciousReplicated<F>>,
    ) -> Result<IPAModulusConvertedInputRow<F, MaliciousReplicated<F>>, Error> {
        let mk_shares = m_ctx.upgrade(mk_shares).await?;
        let is_trigger_bit = m_ctx.upgrade(is_trigger_bit).await?;
        let trigger_value = m_ctx.upgrade(trigger_value).await?;
        Ok(IPAModulusConvertedInputRow {
            mk_shares,
            is_trigger_bit,
            breakdown_key: bk_shares,
            trigger_value,
            _marker: PhantomData::default(),
        })
    }
}

/// # Errors
/// Propagates errors from multiplications
/// # Panics
/// Propagates errors from multiplications
#[allow(dead_code)]
pub async fn ipa<F, T: Arithmetic<F>, MK, BK>(
    ctx: SemiHonestContext<'_, F>,
    input_rows: &[IPAInputRow<F, MK, BK>],
    per_user_credit_cap: u32,
    max_breakdown_key: u128,
    num_multi_bits: u32,
) -> Result<Vec<MCAggregateCreditOutputRow<F, Replicated<F>>>, Error>
where
    F: Field,
    MK: BitArray,
    BK: BitArray,
{
    let (mk_shares, bk_shares): (Vec<_>, Vec<_>) = input_rows
        .iter()
        .map(|x| (x.mk_shares.clone(), x.breakdown_key.clone()))
        .unzip();

    // Breakdown key modulus conversion
    let converted_bk_shares = convert_all_bits(
        &ctx.narrow(&Step::ModulusConversionForBreakdownKeys),
        &convert_all_bits_local(ctx.role(), &bk_shares),
        BK::BITS,
        num_multi_bits,
    )
    .await
    .unwrap();
    let converted_bk_shares = combine_slices(&converted_bk_shares, BK::BITS);

    // Match key modulus conversion, and then sort
    let converted_mk_shares = convert_all_bits(
        &ctx.narrow(&Step::ModulusConversionForMatchKeys),
        &convert_all_bits_local(ctx.role(), &mk_shares),
        MK::BITS,
        num_multi_bits,
    )
    .await
    .unwrap();

    let sort_permutation = generate_permutation_and_reveal_shuffled(
        ctx.narrow(&Step::GenSortPermutationFromMatchKeys),
        &converted_mk_shares,
    )
    .await
    .unwrap();

    let converted_mk_shares = combine_slices(&converted_mk_shares, MK::BITS);

    let combined_match_keys_and_sidecar_data =
        std::iter::zip(converted_mk_shares, converted_bk_shares)
            .into_iter()
            .zip(input_rows)
            .map(
                |((mk_shares, bk_shares), input_row)| IPAModulusConvertedInputRow {
                    mk_shares,
                    is_trigger_bit: input_row.is_trigger_bit.clone(),
                    breakdown_key: bk_shares,
                    trigger_value: input_row.trigger_value.clone(),
                    _marker: PhantomData::default(),
                },
            )
            .collect::<Vec<_>>();

    let sorted_rows = apply_sort_permutation(
        ctx.narrow(&Step::ApplySortPermutation),
        combined_match_keys_and_sidecar_data,
        &sort_permutation,
    )
    .await
    .unwrap();

    let futures = zip(
        repeat(
            ctx.narrow(&Step::ComputeHelperBits)
                .set_total_records(sorted_rows.len() - 1),
        ),
        sorted_rows.iter(),
    )
    .zip(sorted_rows.iter().skip(1))
    .enumerate()
    .map(|(i, ((ctx, row), next_row))| {
        let record_id = RecordId::from(i);
        async move { bitwise_equal(ctx, record_id, &row.mk_shares, &next_row.mk_shares).await }
    });
    let helper_bits = Some(Replicated::ZERO)
        .into_iter()
        .chain(try_join_all(futures).await?);

    let attribution_input_rows = zip(sorted_rows, helper_bits)
        .map(|(row, hb)| MCAccumulateCreditInputRow {
            is_trigger_report: row.is_trigger_bit,
            helper_bit: hb,
            breakdown_key: row.breakdown_key,
            trigger_value: row.trigger_value,
            _marker: PhantomData::default(),
        })
        .collect::<Vec<_>>();

    let accumulated_credits =
        accumulate_credit(ctx.narrow(&Step::AccumulateCredit), &attribution_input_rows).await?;

    let user_capped_credits = credit_capping(
        ctx.narrow(&Step::PerformUserCapping),
        &accumulated_credits,
        per_user_credit_cap,
    )
    .await?;

    aggregate_credit::<F, BK>(
        ctx.narrow(&Step::AggregateCredit),
        &user_capped_credits,
        max_breakdown_key,
        num_multi_bits,
        false,
    )
    .await
}

/// # Errors
/// Propagates errors from multiplications
/// # Panics
/// Propagates errors from multiplications
#[allow(dead_code, clippy::too_many_lines)]
pub async fn ipa_wip_malicious<F, MK, BK>(
    sh_ctx: SemiHonestContext<'_, F>,
    input_rows: &[IPAInputRow<F, MK, BK>],
    per_user_credit_cap: u32,
    max_breakdown_key: u128,
    num_multi_bits: u32,
) -> Result<Vec<MCAggregateCreditOutputRow<F, Replicated<F>>>, Error>
where
    F: Field,
    MK: BitArray,
    BK: BitArray,
{
    let malicious_validator = MaliciousValidator::new(sh_ctx.clone());
    let m_ctx = malicious_validator.context();

    let (mk_shares, bk_shares): (Vec<_>, Vec<_>) = input_rows
        .iter()
        .map(|x| (x.mk_shares.clone(), x.breakdown_key.clone()))
        .unzip();

    // Match key modulus conversion, and then sort
    let converted_mk_shares = convert_all_bits(
        &m_ctx.narrow(&Step::ModulusConversionForMatchKeys),
        &m_ctx
            .upgrade(convert_all_bits_local(m_ctx.role(), &mk_shares))
            .await?,
        MK::BITS,
        num_multi_bits,
    )
    .await
    .unwrap();

    //Validate before calling sort with downgraded context
    let converted_mk_shares = malicious_validator.validate(converted_mk_shares).await?;

    let sort_permutation = malicious_generate_permutation_and_reveal_shuffled(
        sh_ctx.narrow(&Step::GenSortPermutationFromMatchKeys),
        &converted_mk_shares,
    )
    .await
    .unwrap();

    let malicious_validator = MaliciousValidator::new(sh_ctx.narrow(&Step::AfterConvertAllBits));
    let m_ctx = malicious_validator.context();

    let converted_mk_shares = combine_slices(&converted_mk_shares, MK::BITS);

    // Breakdown key modulus conversion
    let converted_bk_shares = convert_all_bits(
        &m_ctx.narrow(&Step::ModulusConversionForBreakdownKeys),
        &m_ctx
            .upgrade(convert_all_bits_local(m_ctx.role(), &bk_shares))
            .await?,
        BK::BITS,
        num_multi_bits,
    )
    .await
    .unwrap();

    let converted_bk_shares = combine_slices(&converted_bk_shares, BK::BITS);

    let combined_match_keys_and_sidecar_data = try_join_all(
        zip(
            repeat(m_ctx.clone()),
            zip(converted_mk_shares, converted_bk_shares),
        )
        .into_iter()
        .zip(input_rows)
        .map(|((m_ctx, (mk_shares, bk_shares)), input_row)| async move {
            IPAModulusConvertedInputRow::<F, Replicated<F>>::upgrade_to_malicious(
                m_ctx.narrow(&Step::IPAModulusConvertedInputRowUpgrade),
                mk_shares,
                input_row.is_trigger_bit.clone(),
                input_row.trigger_value.clone(),
                bk_shares,
            )
            .await
        }),
    )
    .await?;

    let sorted_rows = apply_sort_permutation(
        m_ctx.narrow(&Step::ApplySortPermutation),
        combined_match_keys_and_sidecar_data,
        &sort_permutation,
    )
    .await
    .unwrap();

    let futures = zip(
        repeat(
            m_ctx
                .narrow(&Step::ComputeHelperBits)
                .set_total_records(sorted_rows.len() - 1),
        ),
        sorted_rows.iter(),
    )
    .zip(sorted_rows.iter().skip(1))
    .enumerate()
    .map(|(i, ((m_ctx, row), next_row))| {
        let record_id = RecordId::from(i);
        async move { bitwise_equal(m_ctx, record_id, &row.mk_shares, &next_row.mk_shares).await }
    });
    let helper_bits = Some(MaliciousReplicated::ZERO)
        .into_iter()
        .chain(try_join_all(futures).await?);

    let attribution_input_rows = zip(sorted_rows, helper_bits)
        .map(|(row, hb)| MCAccumulateCreditInputRow {
            is_trigger_report: row.is_trigger_bit,
            helper_bit: hb,
            breakdown_key: row.breakdown_key,
            trigger_value: row.trigger_value,
            _marker: PhantomData::default(),
        })
        .collect::<Vec<_>>();

    let accumulated_credits = accumulate_credit(
        m_ctx.narrow(&Step::AccumulateCredit),
        &attribution_input_rows,
    )
    .await?;

    let user_capped_credits = credit_capping(
        m_ctx.narrow(&Step::PerformUserCapping),
        &accumulated_credits,
        per_user_credit_cap,
    )
    .await?;

    //Validate before calling sort with downgraded context
    let user_capped_credits = malicious_validator.validate(user_capped_credits).await?;

    aggregate_credit::<F, BK>(
        sh_ctx.narrow(&Step::AggregateCredit),
        &user_capped_credits,
        max_breakdown_key,
        num_multi_bits,
        true,
    )
    .await
}
#[cfg(all(test, not(feature = "shuttle")))]
pub mod tests {
    use super::{ipa, ipa_wip_malicious};
    use crate::bits::BitArray;
    use crate::ipa_test_input;
    use crate::protocol::{BreakdownKey, MatchKey};
    use crate::test_fixture::input::GenericReportTestInput;
    use crate::{ff::Fp32BitPrime, rand::thread_rng};
    use crate::{
        ff::{Field, Fp31},
        test_fixture::{Reconstruct, Runner, TestWorld},
    };
    use rand::Rng;

    use crate::secret_sharing::replicated::semi_honest::AdditiveShare as Replicated;

    #[tokio::test]
    #[allow(clippy::missing_panics_doc)]
    pub async fn semi_honest() {
        const COUNT: usize = 5;
        const PER_USER_CAP: u32 = 3;
        const EXPECTED: &[[u128; 2]] = &[[0, 0], [1, 2], [2, 3]];
        const MAX_BREAKDOWN_KEY: u128 = 3;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::new().await;

        let records: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = ipa_test_input!(
            [
                { match_key: 12345, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { match_key: 12345, is_trigger_report: 0, breakdown_key: 2, trigger_value: 0 },
                { match_key: 68362, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 5 },
                { match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 2 },
            ];
            (Fp31, MatchKey, BreakdownKey)
        );

        let result: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = world
            .semi_honest(records, |ctx, input_rows| async move {
                ipa::<Fp31, Replicated<Fp31>, MatchKey, BreakdownKey>(
                    ctx,
                    &input_rows,
                    PER_USER_CAP,
                    MAX_BREAKDOWN_KEY,
                    NUM_MULTI_BITS,
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();

        assert_eq!(EXPECTED.len(), result.len());

        for (i, expected) in EXPECTED.iter().enumerate() {
            assert_eq!(
                *expected,
                [
                    result[i].breakdown_key.as_u128(),
                    result[i].trigger_value.as_u128()
                ]
            );
        }
    }

    #[tokio::test]
    async fn malicious_wip() {
        const COUNT: usize = 5;
        const PER_USER_CAP: u32 = 3;
        const EXPECTED: &[[u128; 2]] = &[[0, 0], [1, 2], [2, 3]];
        const MAX_BREAKDOWN_KEY: u128 = 3;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::new().await;

        let records: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = ipa_test_input!(
            [
                { match_key: 12345, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { match_key: 12345, is_trigger_report: 0, breakdown_key: 2, trigger_value: 0 },
                { match_key: 68362, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 5 },
                { match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 2 },
            ];
            (Fp31, MatchKey, BreakdownKey)
        );

        let result: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = world
            .semi_honest(records, |ctx, input_rows| async move {
                ipa_wip_malicious::<Fp31, MatchKey, BreakdownKey>(
                    ctx,
                    &input_rows,
                    PER_USER_CAP,
                    MAX_BREAKDOWN_KEY,
                    NUM_MULTI_BITS,
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();

        assert_eq!(EXPECTED.len(), result.len());

        for (i, expected) in EXPECTED.iter().enumerate() {
            assert_eq!(
                *expected,
                [
                    result[i].breakdown_key.as_u128(),
                    result[i].trigger_value.as_u128()
                ]
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::missing_panics_doc)]
    #[ignore]
    pub async fn random_ipa_no_result_check() {
        const BATCHSIZE: u128 = 20;
        const PER_USER_CAP: u32 = 10;
        const MAX_BREAKDOWN_KEY: u128 = 8;
        const MAX_TRIGGER_VALUE: u128 = 5;
        const NUM_MULTI_BITS: u32 = 3;

        let max_match_key: u128 = BATCHSIZE / 10;

        let world = TestWorld::new().await;
        let mut rng = thread_rng();

        let mut records = Vec::new();

        for _ in 0..BATCHSIZE {
            records.push(ipa_test_input!(
                {
                    match_key: rng.gen_range(0..max_match_key),
                    is_trigger_report: rng.gen::<u32>(),
                    breakdown_key: rng.gen_range(0..MAX_BREAKDOWN_KEY),
                    trigger_value: rng.gen_range(0..MAX_TRIGGER_VALUE),
                };
                (Fp32BitPrime, MatchKey, BreakdownKey)
            ));
        }
        let result: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = world
            .semi_honest(records, |ctx, input_rows| async move {
                ipa::<Fp32BitPrime, Replicated<Fp32BitPrime>, MatchKey, BreakdownKey>(
                    ctx,
                    &input_rows,
                    PER_USER_CAP,
                    MAX_BREAKDOWN_KEY,
                    NUM_MULTI_BITS,
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();

        assert_eq!(MAX_BREAKDOWN_KEY, result.len() as u128);
    }
}
