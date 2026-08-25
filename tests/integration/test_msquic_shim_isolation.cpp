/**
 * @file tests/integration/test_msquic_shim_isolation.cpp
 * @brief Guard the MSVC/MsQuic and MinGW/Lumen ABI boundary.
 */

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "../../src/platform/windows/msquic_shim/cng_key_journal.h"

namespace {
  namespace cng = lumen::msquic::cng;

  std::string source(const std::filesystem::path &relative) {
    std::ifstream input {std::filesystem::path {SUNSHINE_SOURCE_DIR} / relative};
    EXPECT_TRUE(input.is_open());
    return {std::istreambuf_iterator<char> {input}, std::istreambuf_iterator<char> {}};
  }

  cng::KeyIdentity identity(
    std::u16string provider,
    std::u16string container,
    std::u16string unique_name,
    const bool machine_key = true
  ) {
    return {
      .provider = std::move(provider),
      .container = std::move(container),
      .unique_name = std::move(unique_name),
      .machine_key = machine_key,
    };
  }

  class MemoryJournalStore final: public cng::JournalStore {
  public:
    bool read(std::vector<cng::KeyIdentity> &output) noexcept override {
      if (!read_ok) {
        return false;
      }
      output = entries;
      return true;
    }

    bool write(const std::vector<cng::KeyIdentity> &updated) noexcept override {
      ++writes;
      if (!write_ok) {
        return false;
      }
      entries = updated;
      return true;
    }

    std::vector<cng::KeyIdentity> entries;
    bool read_ok {true};
    bool write_ok {true};
    std::size_t writes {};
  };

  class FakeKeyBackend final: public cng::KeyBackend {
  public:
    struct Fixture {
      cng::KeyIdentity locator;
      std::u16string observed_unique_name;
      Handle handle {};
      bool delete_succeeds {true};
    };

    OpenResult open(const cng::KeyIdentity &requested) noexcept override {
      for (const auto &fixture : fixtures) {
        if (cng::same_locator(fixture.locator, requested)) {
          return {
            .status = OpenStatus::opened,
            .handle = fixture.handle,
            .unique_name = fixture.observed_unique_name,
          };
        }
      }
      return {.status = OpenStatus::missing};
    }

    bool delete_key(const Handle handle) noexcept override {
      delete_calls.push_back(handle);
      for (const auto &fixture : fixtures) {
        if (fixture.handle == handle) {
          return fixture.delete_succeeds;
        }
      }
      const auto found = direct_delete_results.find(handle);
      return found != direct_delete_results.end() && found->second;
    }

    void free_key(const Handle handle) noexcept override {
      free_calls.push_back(handle);
    }

    std::vector<Fixture> fixtures;
    std::map<Handle, bool> direct_delete_results;
    std::vector<Handle> delete_calls;
    std::vector<Handle> free_calls;
  };
}  // namespace

TEST(MsQuicShimIsolation, PortableHeaderHasNoWindowsOrMsQuicDependency) {
  const auto header = source("src/platform/windows/msquic_shim/lumen_msquic_shim.h");
  EXPECT_EQ(header.find("#include <windows.h>"), std::string::npos);
  EXPECT_EQ(header.find("#include <msquic.h>"), std::string::npos);
  EXPECT_NE(header.find("LUMEN_MSQUIC_SHIM_ABI_VERSION 3u"), std::string::npos);
  EXPECT_NE(header.find("lumen_msquic_connection_event"), std::string::npos);
  EXPECT_NE(header.find("lumen_msquic_stream_event"), std::string::npos);
}

TEST(MsQuicShimIsolation, OfficialHeaderIsConfinedToMsvcShimTranslationUnit) {
  const auto shim = source("src/platform/windows/msquic_shim/lumen_msquic_shim.cpp");
  const auto server = source("src/protocol_v3/quic_server.cpp");
  EXPECT_NE(shim.find("#include <msquic.h>"), std::string::npos);
  EXPECT_EQ(server.find("#include <msquic.h>"), std::string::npos);
  EXPECT_EQ(server.find("QUIC_API_ENABLE_PREVIEW_FEATURES"), std::string::npos);
  EXPECT_EQ(server.find("ConnectionExportKeyingMaterial"), std::string::npos);
  EXPECT_NE(server.find("lumen_msquic_shim.h"), std::string::npos);
}

TEST(MsQuicShimIsolation, ProjectIsAnMsvcDllAndStagesPinnedRuntime) {
  const auto project = source("src/platform/windows/msquic_shim/LumenMsQuicShim.vcxproj");
  const auto dependency = source("cmake/dependencies/msquic.cmake");
  const auto targets = source("cmake/targets/common.cmake");
  EXPECT_NE(project.find("<ConfigurationType>DynamicLibrary</ConfigurationType>"), std::string::npos);
  EXPECT_NE(project.find("<PlatformToolset>v143</PlatformToolset>"), std::string::npos);
  EXPECT_NE(dependency.find("Lumen::MsQuicShim"), std::string::npos);
  EXPECT_EQ(dependency.find("add_library(MsQuic::MsQuic"), std::string::npos);
  EXPECT_NE(targets.find("LUMEN_MSQUIC_SHIM_RUNTIME"), std::string::npos);
  EXPECT_NE(targets.find("LUMEN_MSQUIC_LICENSE"), std::string::npos);
}

TEST(MsQuicShimIsolation, OwnedKeyIsJournaledBeforeEscapeAndDeletedExactlyOnce) {
  auto store = std::make_shared<MemoryJournalStore>();
  cng::OwnedKeyJournal journal {store};
  const auto owned = identity(u"Microsoft KSP", u"lumen-import-1", u"unique-1");

  EXPECT_EQ(journal.record_before_escape(owned), cng::Status::success);
  ASSERT_EQ(store->entries, std::vector<cng::KeyIdentity>({owned}));

  FakeKeyBackend backend;
  backend.direct_delete_results.emplace(41, true);
  const auto released = journal.release_owned(owned, 41, backend);

  EXPECT_EQ(released.status, cng::Status::success);
  EXPECT_EQ(released.deleted, 1u);
  EXPECT_EQ(backend.delete_calls, std::vector<cng::KeyBackend::Handle>({41}));
  EXPECT_TRUE(backend.free_calls.empty());
  EXPECT_TRUE(store->entries.empty());
}

TEST(MsQuicShimIsolation, DeleteFailureFreesOnceAndRetainsExactJournalRecord) {
  auto store = std::make_shared<MemoryJournalStore>();
  const auto owned = identity(u"Microsoft KSP", u"lumen-import-2", u"unique-2");
  store->entries.push_back(owned);
  cng::OwnedKeyJournal journal {store};
  FakeKeyBackend backend;
  backend.direct_delete_results.emplace(42, false);

  const auto released = journal.release_owned(owned, 42, backend);

  EXPECT_EQ(released.status, cng::Status::cleanup_incomplete);
  EXPECT_EQ(backend.delete_calls, std::vector<cng::KeyBackend::Handle>({42}));
  EXPECT_EQ(backend.free_calls, std::vector<cng::KeyBackend::Handle>({42}));
  EXPECT_EQ(store->entries, std::vector<cng::KeyIdentity>({owned}));
}

TEST(MsQuicShimIsolation, ReaperDeletesOnlyExactUniqueNameAndNeverUnrelatedKey) {
  auto store = std::make_shared<MemoryJournalStore>();
  const auto exact = identity(u"Microsoft KSP", u"lumen-import-3", u"unique-3");
  const auto stale = identity(u"Microsoft KSP", u"reused-container", u"old-unique");
  store->entries = {exact, stale};
  cng::OwnedKeyJournal journal {store};
  FakeKeyBackend backend;
  backend.fixtures = {
    {.locator = exact, .observed_unique_name = exact.unique_name, .handle = 51, .delete_succeeds = true},
    {.locator = stale, .observed_unique_name = u"unrelated-unique", .handle = 52, .delete_succeeds = true},
  };

  const auto reaped = journal.reap(backend);

  EXPECT_EQ(reaped.status, cng::Status::success);
  EXPECT_EQ(reaped.deleted, 1u);
  EXPECT_EQ(reaped.skipped_unrelated, 1u);
  EXPECT_EQ(backend.delete_calls, std::vector<cng::KeyBackend::Handle>({51}));
  EXPECT_EQ(backend.free_calls, std::vector<cng::KeyBackend::Handle>({52}));
  EXPECT_TRUE(store->entries.empty());
}

TEST(MsQuicShimIsolation, ReaperRetainsFailedDeleteForNextPass) {
  auto store = std::make_shared<MemoryJournalStore>();
  const auto owned = identity(u"Microsoft KSP", u"lumen-import-4", u"unique-4");
  store->entries.push_back(owned);
  cng::OwnedKeyJournal journal {store};
  FakeKeyBackend backend;
  backend.fixtures = {
    {.locator = owned, .observed_unique_name = owned.unique_name, .handle = 61, .delete_succeeds = false},
  };

  const auto reaped = journal.reap(backend);

  EXPECT_EQ(reaped.status, cng::Status::cleanup_incomplete);
  EXPECT_EQ(backend.delete_calls, std::vector<cng::KeyBackend::Handle>({61}));
  EXPECT_EQ(backend.free_calls, std::vector<cng::KeyBackend::Handle>({61}));
  EXPECT_EQ(store->entries, std::vector<cng::KeyIdentity>({owned}));
}

TEST(MsQuicShimIsolation, BinaryJournalRejectsCorruptionAndAmbiguousOwnership) {
  const auto first = identity(u"Microsoft KSP", u"shared-container", u"unique-a");
  auto conflicting = first;
  conflicting.unique_name = u"unique-b";
  std::vector<std::uint8_t> encoded;
  EXPECT_FALSE(cng::serialize({first, conflicting}, encoded));

  ASSERT_TRUE(cng::serialize({first}, encoded));
  encoded.push_back(0xff);
  std::vector<cng::KeyIdentity> decoded;
  EXPECT_FALSE(cng::deserialize(encoded, decoded));
}

TEST(MsQuicShimIsolation, ConfigurationCloseReleasesCredentialOwnedKeyJournal) {
  const auto shim = source("src/platform/windows/msquic_shim/lumen_msquic_shim.cpp");
  const auto header = source("src/platform/windows/msquic_shim/lumen_msquic_shim.h");
  EXPECT_NE(header.find("lumen_msquic_set_cng_journal_path"), std::string::npos);
  EXPECT_NE(shim.find("record_before_escape(identity)"), std::string::npos);
  EXPECT_NE(shim.find("configuration_credentials.extract(handle)"), std::string::npos);
  EXPECT_NE(shim.find("credential->release()"), std::string::npos);
}
