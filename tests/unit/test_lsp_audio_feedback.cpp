/**
 * @file tests/unit/test_lsp_audio_feedback.cpp
 * @brief Focused RFC 8888 audio-ledger overlap accounting tests.
 */

#include "src/protocol_lsp/runtime/audio_sender.h"

#include <gtest/gtest.h>

namespace {
  namespace lsp = lumen::lsp::runtime;
}

TEST(LspAudioFeedback, LostThenReceivedCorrectsLossAndCountsDeliveryExactlyOnce) {
  const auto first = lsp::plan_audio_feedback_transition(
    lsp::AudioFeedbackState::unreported,
    false,
    false,
    false
  );
  ASSERT_TRUE(first.valid);
  EXPECT_EQ(first.next, lsp::AudioFeedbackState::lost);
  EXPECT_EQ(first.lost_packets, 1);
  EXPECT_EQ(first.delivered_packets, 0);
  EXPECT_TRUE(first.retire_in_flight);

  const auto correction = lsp::plan_audio_feedback_transition(
    first.next,
    true,
    false,
    false
  );
  ASSERT_TRUE(correction.valid);
  EXPECT_EQ(correction.next, lsp::AudioFeedbackState::received);
  EXPECT_EQ(correction.lost_packets, -1);
  EXPECT_EQ(correction.delivered_packets, 1);
  EXPECT_FALSE(correction.retire_in_flight);

  const auto duplicate = lsp::plan_audio_feedback_transition(
    correction.next,
    true,
    false,
    false
  );
  ASSERT_TRUE(duplicate.valid);
  EXPECT_EQ(duplicate.delivered_packets, 0);
  EXPECT_EQ(duplicate.lost_packets, 0);
}

TEST(LspAudioFeedback, DuplicateCeUpgradesOnceAndReceivedNeverRevertsToLoss) {
  const auto ce_upgrade = lsp::plan_audio_feedback_transition(
    lsp::AudioFeedbackState::received,
    true,
    false,
    true
  );
  ASSERT_TRUE(ce_upgrade.valid);
  EXPECT_TRUE(ce_upgrade.upgrade_to_ce);
  EXPECT_EQ(ce_upgrade.delivered_packets, 0);

  const auto repeated_ce = lsp::plan_audio_feedback_transition(
    lsp::AudioFeedbackState::received,
    true,
    true,
    true
  );
  ASSERT_TRUE(repeated_ce.valid);
  EXPECT_FALSE(repeated_ce.upgrade_to_ce);

  const auto invalid_loss = lsp::plan_audio_feedback_transition(
    lsp::AudioFeedbackState::received,
    false,
    true,
    false
  );
  EXPECT_FALSE(invalid_loss.valid);
}

TEST(LspAudioFeedback, UnsentTombstoneAcceptsOnlyMissingMetricWithoutAccounting) {
  const auto missing = lsp::plan_audio_feedback_transition(
    lsp::AudioFeedbackState::unsent,
    false,
    false,
    false
  );
  ASSERT_TRUE(missing.valid);
  EXPECT_EQ(missing.next, lsp::AudioFeedbackState::unsent);
  EXPECT_EQ(missing.delivered_packets, 0);
  EXPECT_EQ(missing.lost_packets, 0);

  EXPECT_FALSE(lsp::plan_audio_feedback_transition(lsp::AudioFeedbackState::unsent, true, false, false).valid);
}
