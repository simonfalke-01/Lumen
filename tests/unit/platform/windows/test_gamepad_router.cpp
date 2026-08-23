/**
 * @file tests/unit/platform/windows/test_gamepad_router.cpp
 * @brief Unit tests for tagged Windows gamepad routing.
 */

// local includes
#include "src/platform/windows/gamepad_router.h"

// standard includes
#include <memory>
#include <utility>
#include <vector>

// lib includes
#include <gtest/gtest.h>

namespace {
  using platf::gamepad_arrival_t;
  using platf::gamepad_battery_t;
  using platf::gamepad_id_t;
  using platf::gamepad_motion_t;
  using platf::gamepad_state_t;
  using platf::gamepad_touch_t;
  using namespace platf::win_gamepad;

  /**
   * @brief Mutable counters shared with a fake backend after ownership moves.
   */
  struct backend_observation_t {
    int updates {};  ///< Ordinary state update count.
    int touches {};  ///< Touch event count.
    int motions {};  ///< Motion event count.
    int batteries {};  ///< Battery event count.
    int closes {};  ///< Teardown count.
  };

  /**
   * @brief Fake live backend used to prove router ownership and dispatch.
   */
  class fake_backend_t final: public backend_t {
  public:
    /**
     * @brief Construct a fake backend with deterministic identity.
     *
     * @param kind Backend discriminator.
     * @param profile Profile discriminator.
     * @param generation Slot generation.
     * @param observation Shared counters.
     */
    fake_backend_t(
      backend_kind_e kind,
      profile_kind_e profile,
      std::uint64_t generation,
      std::shared_ptr<backend_observation_t> observation
    ):
        kind_ {kind},
        profile_ {profile},
        observation_ {std::move(observation)} {
      identity_.device_id = generation + 100;
      identity_.token.fill(static_cast<std::uint8_t>(generation));
    }

    backend_kind_e kind() const noexcept override {
      return kind_;
    }

    profile_kind_e profile() const noexcept override {
      return profile_;
    }

    backend_identity_t identity() const noexcept override {
      return identity_;
    }

    bool update(const gamepad_state_t &) override {
      ++observation_->updates;
      return accept_;
    }

    bool touch(const gamepad_touch_t &) override {
      ++observation_->touches;
      return accept_;
    }

    bool motion(const gamepad_motion_t &) override {
      ++observation_->motions;
      return accept_;
    }

    bool battery(const gamepad_battery_t &) override {
      ++observation_->batteries;
      return accept_;
    }

    void close() noexcept override {
      ++observation_->closes;
    }

    /** Whether routed events are accepted. */
    bool accept_ {true};

  private:
    backend_kind_e kind_;  ///< Fake transport kind.
    profile_kind_e profile_;  ///< Fake controller profile.
    backend_identity_t identity_;  ///< Deterministic identity.
    std::shared_ptr<backend_observation_t> observation_;  ///< Shared counters.
  };

  /**
   * @brief Configurable fake factory recording every attempt.
   */
  struct factory_t {
    backend_kind_e kind {backend_kind_e::none};  ///< Backend created on success.
    bool succeed {true};  ///< Whether creation succeeds.
    bool visible_on_failure {};  ///< Failure visibility boundary.
    int calls {};  ///< Number of creation attempts.
    std::vector<profile_kind_e> profiles;  ///< Attempted profiles.
    std::shared_ptr<backend_observation_t> last_observation;  ///< Most recent live backend counters.

    /**
     * @brief Return a router-compatible factory closure.
     *
     * @return Backend creation closure.
     */
    backend_factory_t callback() {
      return [this](
               profile_kind_e profile,
               const gamepad_id_t &,
               const gamepad_arrival_t &,
               platf::feedback_queue_t,
               std::uint64_t generation
             ) {
        ++calls;
        profiles.push_back(profile);
        if (!succeed) {
          return create_result_t {
            .became_visible = visible_on_failure,
            .error = "planned creation failure",
          };
        }
        last_observation = std::make_shared<backend_observation_t>();
        return create_result_t {
          .backend = std::make_unique<fake_backend_t>(kind, profile, generation, last_observation),
        };
      };
    }
  };

  /**
   * @brief Build metadata for a reported controller family.
   *
   * @param type LI_CTYPE_* value.
   * @return Arrival metadata.
   */
  gamepad_arrival_t metadata(std::uint8_t type) {
    return {.type = type};
  }

}  // namespace

TEST(GamepadRouterTest, SelectsEveryExplicitModernProfileForVirtualHid) {
  const std::vector<std::pair<std::string_view, profile_kind_e>> profiles {
    {"generic", profile_kind_e::generic},
    {"xone", profile_kind_e::xbox_one},
    {"xseries", profile_kind_e::xbox_series},
    {"ds4", profile_kind_e::dualshock4},
    {"ds5", profile_kind_e::dualsense},
    {"switch", profile_kind_e::switch_pro},
  };
  for (const auto &[name, expected] : profiles) {
    route_t route;
    std::string error;
    ASSERT_TRUE(select_route(name, "auto", {}, route, error)) << name << ": " << error;
    EXPECT_EQ(route.backend, backend_kind_e::virtual_hid);
    EXPECT_EQ(route.profile, expected);
    EXPECT_FALSE(route.allow_pre_visibility_fallback);
  }
}

TEST(GamepadRouterTest, KeepsXbox360OnVigemAndRejectsForcedConflicts) {
  route_t route;
  std::string error;
  ASSERT_TRUE(select_route("x360", "auto", {}, route, error));
  EXPECT_EQ(route.backend, backend_kind_e::vigem);
  EXPECT_EQ(route.profile, profile_kind_e::xbox_360);

  EXPECT_FALSE(select_route("x360", "virtualhid", {}, route, error));
  EXPECT_NE(error.find("ViGEm"), std::string::npos);
  EXPECT_FALSE(select_route("ds5", "vigem", {}, route, error));
  EXPECT_NE(error.find("Virtual HID"), std::string::npos);
}

TEST(GamepadRouterTest, AutomaticSelectionIsCompatibilityFirst) {
  route_t route;
  std::string error;
  ASSERT_TRUE(select_route("auto", "auto", metadata(LI_CTYPE_XBOX), route, error));
  EXPECT_EQ(route.profile, profile_kind_e::xbox_360);
  EXPECT_EQ(route.backend, backend_kind_e::vigem);

  ASSERT_TRUE(select_route("auto", "auto", metadata(LI_CTYPE_UNKNOWN), route, error));
  EXPECT_EQ(route.profile, profile_kind_e::xbox_360);

  ASSERT_TRUE(select_route("auto", "auto", metadata(LI_CTYPE_PS), route, error));
  EXPECT_EQ(route.profile, profile_kind_e::dualsense);
  EXPECT_EQ(route.backend, backend_kind_e::virtual_hid);
  EXPECT_TRUE(route.allow_pre_visibility_fallback);

  ASSERT_TRUE(select_route("auto", "auto", metadata(LI_CTYPE_NINTENDO), route, error));
  EXPECT_EQ(route.profile, profile_kind_e::switch_pro);
  EXPECT_EQ(route.backend, backend_kind_e::virtual_hid);
  EXPECT_TRUE(route.allow_pre_visibility_fallback);
}

TEST(GamepadRouterTest, ForcedBackendAdjustsOnlyAutomaticProfileBeforeCreation) {
  route_t route;
  std::string error;
  ASSERT_TRUE(select_route("auto", "virtualhid", metadata(LI_CTYPE_XBOX), route, error));
  EXPECT_EQ(route.backend, backend_kind_e::virtual_hid);
  EXPECT_EQ(route.profile, profile_kind_e::xbox_one);
  EXPECT_FALSE(route.allow_pre_visibility_fallback);

  ASSERT_TRUE(select_route("auto", "vigem", metadata(LI_CTYPE_PS), route, error));
  EXPECT_EQ(route.backend, backend_kind_e::vigem);
  EXPECT_EQ(route.profile, profile_kind_e::xbox_360);
  EXPECT_FALSE(route.allow_pre_visibility_fallback);
}

TEST(GamepadRouterTest, AutomaticFallbackOccursOnlyBeforeVhfVisibility) {
  factory_t vhid {.kind = backend_kind_e::virtual_hid, .succeed = false};
  factory_t vigem {.kind = backend_kind_e::vigem};
  router_t router {vhid.callback(), vigem.callback()};
  std::string error;

  ASSERT_TRUE(router.allocate({0, 1}, metadata(LI_CTYPE_PS), "auto", "auto", {}, error)) << error;
  EXPECT_EQ(vhid.calls, 1);
  EXPECT_EQ(vigem.calls, 1);
  EXPECT_NE(error.find("planned creation failure"), std::string::npos);
  EXPECT_NE(error.find("using Xbox 360 through ViGEm"), std::string::npos);
  EXPECT_EQ(router.snapshot(0).backend, backend_kind_e::vigem);
  EXPECT_EQ(router.snapshot(0).profile, profile_kind_e::xbox_360);
}

TEST(GamepadRouterTest, VisibleOrExplicitFailureNeverFallsBack) {
  factory_t visible_vhid {
    .kind = backend_kind_e::virtual_hid,
    .succeed = false,
    .visible_on_failure = true,
  };
  factory_t vigem {.kind = backend_kind_e::vigem};
  router_t first {visible_vhid.callback(), vigem.callback()};
  std::string error;
  EXPECT_FALSE(first.allocate({0, 1}, metadata(LI_CTYPE_PS), "auto", "auto", {}, error));
  EXPECT_EQ(vigem.calls, 0);

  factory_t explicit_vhid {.kind = backend_kind_e::virtual_hid, .succeed = false};
  router_t second {explicit_vhid.callback(), vigem.callback()};
  EXPECT_FALSE(second.allocate({0, 1}, metadata(LI_CTYPE_PS), "ds5", "auto", {}, error));
  EXPECT_EQ(vigem.calls, 0);
}

TEST(GamepadRouterTest, ExactlyOneBackendOwnsAVisibleSlot) {
  factory_t vhid {.kind = backend_kind_e::virtual_hid};
  factory_t vigem {.kind = backend_kind_e::vigem};
  router_t router {vhid.callback(), vigem.callback()};
  std::string error;

  ASSERT_TRUE(router.allocate({2, 0}, metadata(LI_CTYPE_PS), "ds5", "auto", {}, error));
  EXPECT_FALSE(router.allocate({2, 0}, metadata(LI_CTYPE_XBOX), "x360", "auto", {}, error));
  EXPECT_EQ(vhid.calls, 1);
  EXPECT_EQ(vigem.calls, 0);
  EXPECT_EQ(router.snapshot(2).backend, backend_kind_e::virtual_hid);
}

TEST(GamepadRouterTest, RoutesAllStateKindsAndMarksAcceptedState) {
  factory_t vhid {.kind = backend_kind_e::virtual_hid};
  factory_t vigem {.kind = backend_kind_e::vigem};
  router_t router {vhid.callback(), vigem.callback()};
  std::string error;
  ASSERT_TRUE(router.allocate({1, 4}, metadata(LI_CTYPE_PS), "ds5", "auto", {}, error));

  EXPECT_TRUE(router.update(1, {}));
  EXPECT_TRUE(router.touch({.id = {1, 4}}));
  EXPECT_TRUE(router.motion({.id = {1, 4}}));
  EXPECT_TRUE(router.battery({.id = {1, 4}}));
  ASSERT_NE(vhid.last_observation, nullptr);
  EXPECT_EQ(vhid.last_observation->updates, 1);
  EXPECT_EQ(vhid.last_observation->touches, 1);
  EXPECT_EQ(vhid.last_observation->motions, 1);
  EXPECT_EQ(vhid.last_observation->batteries, 1);
  EXPECT_TRUE(router.snapshot(1).accepted_state);
}

TEST(GamepadRouterTest, TeardownInvalidatesGenerationAndDrainsBeforeReuse) {
  factory_t vhid {.kind = backend_kind_e::virtual_hid};
  factory_t vigem {.kind = backend_kind_e::vigem};
  router_t router {vhid.callback(), vigem.callback()};
  std::string error;
  ASSERT_TRUE(router.allocate({3, 1}, metadata(LI_CTYPE_PS), "ds5", "auto", {}, error));
  const auto first = router.snapshot(3);
  const auto first_observation = vhid.last_observation;

  router.free(3);
  const auto empty = router.snapshot(3);
  EXPECT_EQ(empty.backend, backend_kind_e::none);
  EXPECT_GT(empty.generation, first.generation);
  EXPECT_EQ(first_observation->closes, 1);

  ASSERT_TRUE(router.allocate({3, 2}, metadata(LI_CTYPE_PS), "ds5", "auto", {}, error));
  const auto second = router.snapshot(3);
  EXPECT_GT(second.generation, empty.generation);
  EXPECT_NE(second.identity.device_id, first.identity.device_id);
  EXPECT_NE(second.identity.token, first.identity.token);
}

TEST(GamepadRouterTest, RejectsOutOfRangeSlotsAndUnknownNames) {
  factory_t vhid {.kind = backend_kind_e::virtual_hid};
  factory_t vigem {.kind = backend_kind_e::vigem};
  router_t router {vhid.callback(), vigem.callback()};
  std::string error;
  EXPECT_FALSE(router.allocate({-1, 0}, {}, "auto", "auto", {}, error));
  EXPECT_FALSE(router.allocate({static_cast<int>(platf::MAX_GAMEPADS), 0}, {}, "auto", "auto", {}, error));

  route_t route;
  EXPECT_FALSE(select_route("bogus", "auto", {}, route, error));
  EXPECT_FALSE(select_route("auto", "bogus", {}, route, error));
}
