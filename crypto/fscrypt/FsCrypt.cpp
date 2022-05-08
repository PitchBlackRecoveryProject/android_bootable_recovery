/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "FsCrypt.h"

#include "KeyStorage.h"
#include "KeyUtil.h"
#include "Utils.h"
#include "VoldUtil.h"

#include <algorithm>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <selinux/android.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <private/android_filesystem_config.h>
#include <private/android_projectid_config.h>

#include "android/os/IVold.h"

#define EMULATED_USES_SELINUX 0
#define MANAGE_MISC_DIRS 0

#include <cutils/fs.h>
#include <cutils/properties.h>

#include <fscrypt/fscrypt.h>
#include <keyutils.h>
#include <libdm/dm.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

#include "fscrypt-common.h"

using android::base::Basename;
using android::base::Realpath;
using android::base::StartsWith;
using android::base::StringPrintf;
using android::fs_mgr::GetEntryForMountPoint;
using ::BuildDataPath;
using ::IsFilesystemSupported;
using ::kEmptyAuthentication;
using ::KeyBuffer;
using ::KeyGeneration;
using ::retrieveKey;
using ::retrieveOrGenerateKey;
using ::SetQuotaInherit;
using ::SetQuotaProjectId;
using ::writeStringToFile;
using namespace android::fscrypt;
using namespace android::dm;

// Map user ids to encryption policies
std::map<userid_t, EncryptionPolicy> s_de_policies;
std::map<userid_t, EncryptionPolicy> s_ce_policies;
std::string de_key_raw_ref;

namespace {

const std::string device_key_dir = std::string() + DATA_MNT_POINT + fscrypt_unencrypted_folder;
const std::string device_key_path = device_key_dir + "/key";
const std::string device_key_temp = device_key_dir + "/temp";

const std::string user_key_dir = std::string() + DATA_MNT_POINT + "/misc/vold/user_keys";
const std::string user_key_temp = user_key_dir + "/temp";
const std::string prepare_subdirs_path = "/system/bin/vold_prepare_subdirs";

const std::string systemwide_volume_key_dir =
    std::string() + DATA_MNT_POINT + "/misc/vold/volume_keys";

// Some users are ephemeral, don't try to wipe their keys from disk
std::set<userid_t> s_ephemeral_users;

}  // namespace

// Returns KeyGeneration suitable for key as described in EncryptionOptions
static KeyGeneration makeGen(const EncryptionOptions& options) {
    return KeyGeneration{FSCRYPT_MAX_KEY_SIZE, true, options.use_hw_wrapped_key};
}

static bool fscrypt_is_emulated() {
    return property_get_bool("persist.sys.emulate_fbe", false);
}

static const char* escape_empty(const std::string& value) {
    return value.empty() ? "null" : value.c_str();
}

static std::string get_de_key_path(userid_t user_id) {
    return StringPrintf("%s/de/%d", user_key_dir.c_str(), user_id);
}

static std::string get_ce_key_directory_path(userid_t user_id) {
    return StringPrintf("%s/ce/%d", user_key_dir.c_str(), user_id);
}

// Returns the keys newest first
static std::vector<std::string> get_ce_key_paths(const std::string& directory_path) {
    auto dirp = std::unique_ptr<DIR, int (*)(DIR*)>(opendir(directory_path.c_str()), closedir);
    if (!dirp) {
        PLOG(ERROR) << "Unable to open ce key directory: " + directory_path;
        return std::vector<std::string>();
    }
    std::vector<std::string> result;
    for (;;) {
        errno = 0;
        auto const entry = readdir(dirp.get());
        if (!entry) {
            if (errno) {
                PLOG(ERROR) << "Unable to read ce key directory: " + directory_path;
                return std::vector<std::string>();
            }
            break;
        }
        if (entry->d_type != DT_DIR || entry->d_name[0] != 'c') {
            LOG(INFO) << "Skipping non-key " << entry->d_name;
            continue;
        }
        result.emplace_back(directory_path + "/" + entry->d_name);
    }
    std::sort(result.begin(), result.end());
    std::reverse(result.begin(), result.end());
    return result;
}

static std::string get_ce_key_current_path(const std::string& directory_path) {
    return directory_path + "/current";
}

static bool get_ce_key_new_path(const std::string& directory_path,
                                const std::vector<std::string>& paths, std::string* ce_key_path) {
    if (paths.empty()) {
        *ce_key_path = get_ce_key_current_path(directory_path);
        return true;
    }
    for (unsigned int i = 0; i < UINT_MAX; i++) {
        auto const candidate = StringPrintf("%s/cx%010u", directory_path.c_str(), i);
        if (paths[0] < candidate) {
            *ce_key_path = candidate;
            return true;
        }
    }
    return false;
}

// Discard all keys but the named one; rename it to canonical name.
// No point in acting on errors in this; ignore them.
static void fixate_user_ce_key(const std::string& directory_path, const std::string& to_fix,
                               const std::vector<std::string>& paths) {
    for (auto const other_path : paths) {
        if (other_path != to_fix) {
            ::destroyKey(other_path);
        }
    }
    auto const current_path = get_ce_key_current_path(directory_path);
    if (to_fix != current_path) {
        LOG(INFO) << "Renaming " << to_fix << " to " << current_path;
        if (rename(to_fix.c_str(), current_path.c_str()) != 0) {
            PLOG(WARNING) << "Unable to rename " << to_fix << " to " << current_path;
            return;
        }
    }
    ::FsyncDirectory(directory_path);
}

static bool read_and_fixate_user_ce_key(userid_t user_id,
                                        const ::KeyAuthentication& auth,
                                        KeyBuffer* ce_key) {
    auto const directory_path = get_ce_key_directory_path(user_id);
    auto const paths = get_ce_key_paths(directory_path);
    for (auto const ce_key_path : paths) {
        LOG(INFO) << "Trying user CE key " << ce_key_path;
        if (retrieveKey(ce_key_path, auth, ce_key, true)) {
            LOG(INFO) << "Successfully retrieved key";
            fixate_user_ce_key(directory_path, ce_key_path, paths);
            return true;
        }
    }
    LOG(ERROR) << "Failed to find working ce key for user " << user_id;
    return false;
}

static bool IsEmmcStorage(const std::string& blk_device) {
    // Handle symlinks.
    std::string real_path;
    if (!Realpath(blk_device, &real_path)) {
        real_path = blk_device;
    }

    // Handle logical volumes.
    auto& dm = DeviceMapper::Instance();
    for (;;) {
        auto parent = dm.GetParentBlockDeviceByPath(real_path);
        if (!parent.has_value()) break;
        real_path = *parent;
    }

    // Now we should have the "real" block device.
    LOG(INFO) << "IsEmmcStorage(): blk_device = " << blk_device << ", real_path=" << real_path;
    return StartsWith(Basename(real_path), "mmcblk");
}

// Retrieve the options to use for encryption policies on the /data filesystem.
static bool get_data_file_encryption_options(EncryptionOptions* options) {
    if (fstab_default.empty()) {
        if (!ReadDefaultFstab(&fstab_default)) {
            PLOG(ERROR) << "Failed to open default fstab";
            return false;
        }
    }
    auto entry = GetEntryForMountPoint(&fstab_default, DATA_MNT_POINT);
    if (entry == nullptr) {
        LOG(ERROR) << "No mount point entry for " << DATA_MNT_POINT;
        return false;
    }
    if (!ParseOptions(entry->encryption_options, options)) {
        LOG(ERROR) << "Unable to parse encryption options for " << DATA_MNT_POINT ": "
                   << entry->encryption_options;
        return false;
    }
    if (options->version == 1) {
        options->use_hw_wrapped_key =
            GetEntryForMountPoint(&fstab_default, DATA_MNT_POINT)->fs_mgr_flags.wrapped_key;
    }
    if ((options->flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32) &&
        !IsEmmcStorage(entry->blk_device)) {
        LOG(ERROR) << "The emmc_optimized encryption flag is only allowed on eMMC storage.  Remove "
                      "this flag from the device's fstab";
        return false;
    }
    return true;
}

static bool install_storage_key(const std::string& mountpoint, const EncryptionOptions& options,
                                const KeyBuffer& key, EncryptionPolicy* policy) {
    KeyBuffer ephemeral_wrapped_key;
    if (options.use_hw_wrapped_key) {
        if (!exportWrappedStorageKey(key, &ephemeral_wrapped_key)) {
            LOG(ERROR) << "Failed to get ephemeral wrapped key";
            return false;
        }
    }
    return installKey(mountpoint, options, options.use_hw_wrapped_key ? ephemeral_wrapped_key : key,
                      policy);
}

// Retrieve the options to use for encryption policies on adoptable storage.
static bool get_volume_file_encryption_options(EncryptionOptions* options) {
    // If we give the empty string, libfscrypt will use the default (currently XTS)
    auto contents_mode = android::base::GetProperty("ro.crypto.volume.contents_mode", "");
    // HEH as default was always a mistake. Use the libfscrypt default (CTS)
    // for devices launching on versions above Android 10.
    auto first_api_level = GetFirstApiLevel();
    constexpr uint64_t pre_gki_level = 29;
    auto filenames_mode =
            android::base::GetProperty("ro.crypto.volume.filenames_mode",
                                       first_api_level > pre_gki_level ? "" : "aes-256-heh");
    auto options_string = android::base::GetProperty("ro.crypto.volume.options",
                                                     contents_mode + ":" + filenames_mode);
    if (!ParseOptionsForApiLevel(first_api_level, options_string, options)) {
        LOG(ERROR) << "Unable to parse volume encryption options: " << options_string;
        return false;
    }
    if (options->flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32) {
        LOG(ERROR) << "The emmc_optimized encryption flag is only allowed on eMMC storage.  Remove "
                      "this flag from ro.crypto.volume.options";
        return false;
    }
    return true;
}

bool is_metadata_wrapped_key_supported() {
    if (fstab_default.empty()) {
        if (!ReadDefaultFstab(&fstab_default)) {
            PLOG(ERROR) << "Failed to open default fstab";
            return false;
        }
    }
    return GetEntryForMountPoint(&fstab_default, METADATA_MNT_POINT)->fs_mgr_flags.wrapped_key;
}

static bool read_and_install_user_ce_key(userid_t user_id,
                                         const ::KeyAuthentication& auth) {
    if (s_ce_policies.count(user_id) != 0) return true;
    EncryptionOptions options;
    if (!get_data_file_encryption_options(&options)) return false;
    KeyBuffer ce_key;
    if (!read_and_fixate_user_ce_key(user_id, auth, &ce_key)) return false;
    EncryptionPolicy ce_policy;
    if (!install_storage_key(DATA_MNT_POINT, options, ce_key, &ce_policy)) return false;
    s_ce_policies[user_id] = ce_policy;
    LOG(INFO) << "Installed ce key for user " << user_id;
    return true;
}

static bool prepare_dir(const std::string& dir, mode_t mode, uid_t uid, gid_t gid) {
    LOG(INFO) << "Preparing: " << dir;
    if (fs_prepare_dir(dir.c_str(), mode, uid, gid) != 0) {
        PLOG(ERROR) << "Failed to prepare " << dir;
        return false;
    }
    return true;
}

static bool destroy_dir(const std::string& dir) {
    LOG(INFO) << "Destroying: " << dir;
    if (rmdir(dir.c_str()) != 0 && errno != ENOENT) {
        PLOG(ERROR) << "Failed to destroy " << dir;
        return false;
    }
    return true;
}

// NB this assumes that there is only one thread listening for crypt commands, because
// it creates keys in a fixed location.
static bool create_and_install_user_keys(userid_t user_id, bool create_ephemeral) {
    LOG(INFO) << "fscrypt::create_and_install_user_keys";
    EncryptionOptions options;
    if (!get_data_file_encryption_options(&options)) return false;
    KeyBuffer de_key, ce_key;
    if (!generateStorageKey(makeGen(options), &de_key)) return false;
    if (!generateStorageKey(makeGen(options), &ce_key)) return false;
    if (create_ephemeral) {
        // If the key should be created as ephemeral, don't store it.
        s_ephemeral_users.insert(user_id);
    } else {
        auto const directory_path = get_ce_key_directory_path(user_id);
        if (!prepare_dir(directory_path, 0700, AID_ROOT, AID_ROOT)) return false;
        auto const paths = get_ce_key_paths(directory_path);
        std::string ce_key_path;
        if (!get_ce_key_new_path(directory_path, paths, &ce_key_path)) return false;
        if (!::storeKeyAtomically(ce_key_path, user_key_temp, kEmptyAuthentication,
                                               ce_key))
            return false;
        fixate_user_ce_key(directory_path, ce_key_path, paths);
        // Write DE key second; once this is written, all is good.
        if (!::storeKeyAtomically(get_de_key_path(user_id), user_key_temp,
                                               kEmptyAuthentication, de_key))
            return false;
    }
    EncryptionPolicy de_policy;
    if (!install_storage_key(DATA_MNT_POINT, options, de_key, &de_policy)) return false;
    s_de_policies[user_id] = de_policy;
    LOG(INFO) << "fscrypt::added de_policy";
    EncryptionPolicy ce_policy;
    if (!install_storage_key(DATA_MNT_POINT, options, ce_key, &ce_policy)) return false;
    s_ce_policies[user_id] = ce_policy;
    LOG(INFO) << "Created keys for user " << user_id;
    return true;
}

bool lookup_policy(const std::map<userid_t, EncryptionPolicy>& key_map, userid_t user_id,
                          EncryptionPolicy* policy) {
    auto refi = key_map.find(user_id);
    if (refi == key_map.end()) {
        LOG(ERROR) << "Cannot find key for " << user_id;
        return false;
    }
    *policy = refi->second;
    return true;
}

static bool is_numeric(const char* name) {
    for (const char* p = name; *p != '\0'; p++) {
        if (!isdigit(*p)) return false;
    }
    return true;
}

static bool load_all_de_keys() {
    LOG(INFO) << "fscrypt::load_all_de_keys";
    EncryptionOptions options;
    if (!get_data_file_encryption_options(&options)) return false;
    auto de_dir = user_key_dir + "/de";
    auto dirp = std::unique_ptr<DIR, int (*)(DIR*)>(opendir(de_dir.c_str()), closedir);
    if (!dirp) {
        PLOG(ERROR) << "Unable to read de key directory";
        return false;
    }
    for (;;) {
        errno = 0;
        auto entry = readdir(dirp.get());
        if (!entry) {
            if (errno) {
                PLOG(ERROR) << "Unable to read de key directory";
                return false;
            }
            break;
        }
        if (entry->d_type != DT_DIR || !is_numeric(entry->d_name)) {
            LOG(INFO) << "Skipping non-de-key " << entry->d_name;
            continue;
        }
        userid_t user_id = std::stoi(entry->d_name);
        auto key_path = de_dir + "/" + entry->d_name;
        KeyBuffer de_key;
        if (!retrieveKey(key_path, kEmptyAuthentication, &de_key, true)) return false;
        EncryptionPolicy de_policy;
        if (!install_storage_key(DATA_MNT_POINT, options, de_key, &de_policy)) return false;
        auto ret = s_de_policies.insert({user_id, de_policy});
        LOG(INFO) << "fscrypt::load_all_de_keys::s_de_policies::size::" << s_de_policies.size();
        if (!ret.second && ret.first->second != de_policy) {
            LOG(INFO) << "DE policy for user" << user_id << " changed";
            return false;
        }
        LOG(INFO) << "Installed de key for user " << user_id;
        std::string user_prop = "twrp.user." + std::to_string(user_id) + ".decrypt";
        property_set(user_prop.c_str(), "0");
    }
    // fscrypt:TODO: go through all DE directories, ensure that all user dirs have the
    // correct policy set on them, and that no rogue ones exist.
    return true;
}

// Attempt to reinstall CE keys for users that we think are unlocked.
static bool try_reload_ce_keys() {
    for (const auto& it : s_ce_policies) {
        if (!::reloadKeyFromSessionKeyring(DATA_MNT_POINT, it.second)) {
            LOG(ERROR) << "Failed to load CE key from session keyring for user " << it.first;
            return false;
        }
    }
    return true;
}

bool fscrypt_initialize_systemwide_keys() {
    LOG(INFO) << "fscrypt_initialize_systemwide_keys";

    EncryptionOptions options;
    if (!get_data_file_encryption_options(&options)) return false;

    KeyBuffer device_key;
    if (!retrieveOrGenerateKey(device_key_path, device_key_temp, kEmptyAuthentication,
                               makeGen(options), &device_key))
        return false;

    EncryptionPolicy device_policy;
    if (!install_storage_key(DATA_MNT_POINT, options, device_key, &device_policy)) return false;

    std::string options_string;
    if (!OptionsToString(device_policy.options, &options_string)) {
        LOG(ERROR) << "Unable to serialize options";
        return false;
    }
    std::string options_filename = std::string(DATA_MNT_POINT) + fscrypt_key_mode;
    if (!::writeStringToFile(options_string, options_filename)) return false;

    std::string ref_filename = std::string(DATA_MNT_POINT) + fscrypt_key_ref;
    de_key_raw_ref = device_policy.key_raw_ref;
    if (!::writeStringToFile(device_policy.key_raw_ref, ref_filename)) return false;
    LOG(INFO) << "Wrote system DE key reference to:" << ref_filename;

    KeyBuffer per_boot_key;
    if (!generateStorageKey(makeGen(options), &per_boot_key)) return false;
    EncryptionPolicy per_boot_policy;
    if (!install_storage_key(DATA_MNT_POINT, options, per_boot_key, &per_boot_policy)) return false;
    std::string per_boot_ref_filename = std::string("/data") + fscrypt_key_per_boot_ref;
    if (!::writeStringToFile(per_boot_policy.key_raw_ref, per_boot_ref_filename))
        return false;
    LOG(INFO) << "Wrote per boot key reference to:" << per_boot_ref_filename;

    if (!::FsyncDirectory(device_key_dir)) return false;
    return true;
}

bool fscrypt_init_user0() {
    if (fstab_default.empty()) {
        if (!ReadDefaultFstab(&fstab_default)) {
            PLOG(ERROR) << "Failed to open default fstab";
            return -1;
        }
    }
    LOG(INFO) << "fscrypt_init_user0";
    if (fscrypt_is_native()) {
        if (!prepare_dir(user_key_dir, 0700, AID_ROOT, AID_ROOT)) return false;
        if (!prepare_dir(user_key_dir + "/ce", 0700, AID_ROOT, AID_ROOT)) return false;
        if (!prepare_dir(user_key_dir + "/de", 0700, AID_ROOT, AID_ROOT)) return false;
        if (!::pathExists(get_de_key_path(0))) {
            if (!create_and_install_user_keys(0, false)) return false;
        }
        // TODO: switch to loading only DE_0 here once framework makes
        // explicit calls to install DE keys for secondary users
        if (!load_all_de_keys()) return false;
    }
    // We can only safely prepare DE storage here, since CE keys are probably
    // entangled with user credentials.  The framework will always prepare CE
    // storage once CE keys are installed.
    LOG(INFO) << "attempting fscrypt_prepare_user_storage";
    if (!fscrypt_prepare_user_storage("", 0, 0, android::os::IVold::STORAGE_FLAG_DE)) {
        LOG(ERROR) << "Failed to prepare user 0 storage";
        return false;
    }

    // If this is a non-FBE device that recently left an emulated mode,
    // restore user data directories to known-good state.
    if (!fscrypt_is_native() && !fscrypt_is_emulated()) {
        LOG(INFO) << "unlocking data media";
        fscrypt_unlock_user_key(0, 0, "!", "!");
    }

    // In some scenarios (e.g. userspace reboot) we might unmount userdata
    // without doing a hard reboot. If CE keys were stored in fs keyring then
    // they will be lost after unmount. Attempt to re-install them.
    if (fscrypt_is_native() && ::isFsKeyringSupported()) {
        LOG(INFO) << "reloading ce keys";
        if (!try_reload_ce_keys()) return false;
    }

    return true;
}

bool fscrypt_vold_create_user_key(userid_t user_id, int serial, bool ephemeral) {
    LOG(INFO) << "fscrypt_vold_create_user_key for " << user_id << " serial " << serial;
    if (!fscrypt_is_native()) {
        return true; 
    }
    // FIXME test for existence of key that is not loaded yet
    if (s_ce_policies.count(user_id) != 0) {
        LOG(ERROR) << "Already exists, can't fscrypt_vold_create_user_key for " << user_id
                   << " serial " << serial;
        // FIXME should we fail the command?
        return true;
    }
    if (!create_and_install_user_keys(user_id, ephemeral)) {
        return false;
    }
    return true;
}

// "Lock" all encrypted directories whose key has been removed.  This is needed
// in the case where the keys are being put in the session keyring (rather in
// the newer filesystem-level keyrings), because removing a key from the session
// keyring doesn't affect inodes in the kernel's inode cache whose per-file key
// was already set up.  So to remove the per-file keys and make the files
// "appear encrypted", these inodes must be evicted.
//
// To do this, sync() to clean all dirty inodes, then drop all reclaimable slab
// objects systemwide.  This is overkill, but it's the best available method
// currently.  Don't use drop_caches mode "3" because that also evicts pagecache
// for in-use files; all files relevant here are already closed and sync'ed.
static void drop_caches_if_needed() {
    if (::isFsKeyringSupported()) {
        return;
    }
    sync();
    if (!writeStringToFile("2", "/proc/sys/vm/drop_caches")) {
        PLOG(ERROR) << "Failed to drop caches during key eviction";
    }
}

static bool evict_ce_key(userid_t user_id) {
    bool success = true;
    EncryptionPolicy policy;
    // If we haven't loaded the CE key, no need to evict it.
    if (lookup_policy(s_ce_policies, user_id, &policy)) {
        success &= ::evictKey(DATA_MNT_POINT, policy);
        drop_caches_if_needed();
    }
    s_ce_policies.erase(user_id);
    return success;
}

bool fscrypt_destroy_user_key(userid_t user_id) {
    LOG(INFO) << "fscrypt_destroy_user_key(" << user_id << ")";
    if (!fscrypt_is_native()) {
        return true;
    }
    bool success = true;
    success &= evict_ce_key(user_id);
    EncryptionPolicy de_policy;
    success &= lookup_policy(s_de_policies, user_id, &de_policy) &&
               ::evictKey(DATA_MNT_POINT, de_policy);
    s_de_policies.erase(user_id);
    auto it = s_ephemeral_users.find(user_id);
    if (it != s_ephemeral_users.end()) {
        s_ephemeral_users.erase(it);
    } else {
        for (auto const path : get_ce_key_paths(get_ce_key_directory_path(user_id))) {
            success &= ::destroyKey(path);
        }
        auto de_key_path = get_de_key_path(user_id);
        if (::pathExists(de_key_path)) {
            success &= ::destroyKey(de_key_path);
        } else {
            LOG(INFO) << "Not present so not erasing: " << de_key_path;
        }
    }
    return success;
}

static bool emulated_lock(const std::string& path) {
    if (chmod(path.c_str(), 0000) != 0) {
        PLOG(ERROR) << "Failed to chmod " << path;
        return false;
    }
#if EMULATED_USES_SELINUX
    if (setfilecon(path.c_str(), "u:object_r:storage_stub_file:s0") != 0) {
        PLOG(WARNING) << "Failed to setfilecon " << path;
        return false;
    }
#endif
    return true;
}

static bool emulated_unlock(const std::string& path, mode_t mode) {
    if (chmod(path.c_str(), mode) != 0) {
        PLOG(ERROR) << "Failed to chmod " << path;
        // FIXME temporary workaround for b/26713622
        if (fscrypt_is_emulated()) return false;
    }
#if EMULATED_USES_SELINUX
    if (selinux_android_restorecon(path.c_str(), SELINUX_ANDROID_RESTORECON_FORCE) != 0) {
        PLOG(WARNING) << "Failed to restorecon " << path;
        // FIXME temporary workaround for b/26713622
        if (fscrypt_is_emulated()) return false;
    }
#endif
    return true;
}

static bool parse_hex(const std::string& hex, std::string* result) {
    if (hex == "!") {
        *result = "";
        return true;
    }
    if (::HexToStr(hex, *result) != 0) {
        LOG(ERROR) << "Invalid FBE hex string";  // Don't log the string for security reasons
        return false;
    }
    return true;
}

static std::optional<::KeyAuthentication> authentication_from_hex(
        const std::string& token_hex, const std::string& secret_hex) {
    std::string token, secret;
    if (!parse_hex(token_hex, &token)) return std::optional<::KeyAuthentication>();
    if (!parse_hex(secret_hex, &secret)) return std::optional<::KeyAuthentication>();
    if (secret.empty()) {
        return kEmptyAuthentication;
    } else {
        return ::KeyAuthentication(token, secret);
    }
}

static std::string volkey_path(const std::string& misc_path, const std::string& volume_uuid) {
    return misc_path + "/vold/volume_keys/" + volume_uuid + "/default";
}

static std::string volume_secdiscardable_path(const std::string& volume_uuid) {
    return systemwide_volume_key_dir + "/" + volume_uuid + "/secdiscardable";
}

static bool read_or_create_volkey(const std::string& misc_path, const std::string& volume_uuid,
                                  EncryptionPolicy* policy) {
    auto secdiscardable_path = volume_secdiscardable_path(volume_uuid);
    std::string secdiscardable_hash;
    if (::pathExists(secdiscardable_path)) {
        if (!readSecdiscardable(secdiscardable_path, &secdiscardable_hash))
            return false;
    } else {
        if (fs_mkdirs(secdiscardable_path.c_str(), 0700) != 0) {
            PLOG(ERROR) << "Creating directories for: " << secdiscardable_path;
            return false;
        }
        if (!::createSecdiscardable(secdiscardable_path, &secdiscardable_hash))
            return false;
    }
    auto key_path = volkey_path(misc_path, volume_uuid);
    if (fs_mkdirs(key_path.c_str(), 0700) != 0) {
        PLOG(ERROR) << "Creating directories for: " << key_path;
        return false;
    }
    ::KeyAuthentication auth("", secdiscardable_hash);

    EncryptionOptions options;
    if (!get_volume_file_encryption_options(&options)) return false;
    KeyBuffer key;
    if (!retrieveOrGenerateKey(key_path, key_path + "_tmp", auth, makeGen(options), &key))
        return false;
    if (!install_storage_key(BuildDataPath(volume_uuid), options, key, policy)) return false;
    return true;
}

static bool destroy_volkey(const std::string& misc_path, const std::string& volume_uuid) {
    auto path = volkey_path(misc_path, volume_uuid);
    if (!::pathExists(path)) return true;
    return ::destroyKey(path);
}

static bool fscrypt_rewrap_user_key(userid_t user_id, int serial,
                                    const ::KeyAuthentication& retrieve_auth,
                                    const ::KeyAuthentication& store_auth) {
    if (s_ephemeral_users.count(user_id) != 0) return true;
    auto const directory_path = get_ce_key_directory_path(user_id);
    KeyBuffer ce_key;
    std::string ce_key_current_path = get_ce_key_current_path(directory_path);
    if (retrieveKey(ce_key_current_path, retrieve_auth, &ce_key, true)) {
        LOG(INFO) << "Successfully retrieved key";
        // TODO(147732812): Remove this once Locksettingservice is fixed.
        // Currently it calls fscrypt_clear_user_key_auth with a secret when lockscreen is
        // changed from swipe to none or vice-versa
    } else if (retrieveKey(ce_key_current_path, kEmptyAuthentication, &ce_key, true)) {
        LOG(INFO) << "Successfully retrieved key with empty auth";
    } else {
        LOG(ERROR) << "Failed to retrieve key for user " << user_id;
        return false;
    }
    auto const paths = get_ce_key_paths(directory_path);
    std::string ce_key_path;
    if (!get_ce_key_new_path(directory_path, paths, &ce_key_path)) return false;
    if (!::storeKeyAtomically(ce_key_path, user_key_temp, store_auth, ce_key))
        return false;
    if (!::FsyncDirectory(directory_path)) return false;
    return true;
}

bool fscrypt_add_user_key_auth(userid_t user_id, int serial, const std::string& token_hex,
                               const std::string& secret_hex) {
    LOG(INFO) << "fscrypt_add_user_key_auth " << user_id << " serial=" << serial
               << " token_present=" << (token_hex != "!");
    if (!fscrypt_is_native()) return true;
    auto auth = authentication_from_hex(token_hex, secret_hex);
    if (!auth) return false;
    return fscrypt_rewrap_user_key(user_id, serial, kEmptyAuthentication, *auth);
}

bool fscrypt_clear_user_key_auth(userid_t user_id, int serial, const std::string& token_hex,
                                 const std::string& secret_hex) {
    LOG(INFO) << "fscrypt_clear_user_key_auth " << user_id << " serial=" << serial
               << " token_present=" << (token_hex != "!");
    if (!fscrypt_is_native()) return true;
    auto auth = authentication_from_hex(token_hex, secret_hex);
    if (!auth) return false;
    return fscrypt_rewrap_user_key(user_id, serial, *auth, kEmptyAuthentication);
}

bool fscrypt_fixate_newest_user_key_auth(userid_t user_id) {
    LOG(INFO) << "fscrypt_fixate_newest_user_key_auth " << user_id;
    if (!fscrypt_is_native()) return true;
    if (s_ephemeral_users.count(user_id) != 0) return true;
    auto const directory_path = get_ce_key_directory_path(user_id);
    auto const paths = get_ce_key_paths(directory_path);
    if (paths.empty()) {
        LOG(ERROR) << "No ce keys present, cannot fixate for user " << user_id;
        return false;
    }
    fixate_user_ce_key(directory_path, paths[0], paths);
    return true;
}

// TODO: rename to 'install' for consistency, and take flags to know which keys to install
bool fscrypt_unlock_user_key(userid_t user_id, int serial, const std::string& token_hex,
                             const std::string& secret_hex) {
    LOG(INFO) << "fscrypt_unlock_user_key " << user_id << " serial=" << serial
               << " token_present=" << (token_hex != "!");
    if (fscrypt_is_native()) {
        if (s_ce_policies.count(user_id) != 0) {
            LOG(WARNING) << "Tried to unlock already-unlocked key for user " << user_id;
            return true;
        }
        auto auth = authentication_from_hex(token_hex, secret_hex);
        if (!auth) return false;
        if (!read_and_install_user_ce_key(user_id, *auth)) {
            LOG(ERROR) << "Couldn't read key for " << user_id;
            return false;
        }
    } else {
        // When in emulation mode, we just use chmod. However, we also
        // unlock directories when not in emulation mode, to bring devices
        // back into a known-good state.
        if (!emulated_unlock(::BuildDataSystemCePath(user_id), 0771) ||
            !emulated_unlock(::BuildDataMiscCePath(user_id), 01771) ||
            !emulated_unlock(::BuildDataMediaCePath("", user_id), 0770) ||
            !emulated_unlock(::BuildDataUserCePath("", user_id), 0771)) {
            LOG(ERROR) << "Failed to unlock user " << user_id;
            return false;
        }
    }
    return true;
}

// TODO: rename to 'evict' for consistency
bool fscrypt_lock_user_key(userid_t user_id) {
    LOG(INFO) << "fscrypt_lock_user_key " << user_id;
    if (fscrypt_is_native()) {
        return evict_ce_key(user_id);
    } else if (fscrypt_is_emulated()) {
        // When in emulation mode, we just use chmod
        if (!emulated_lock(::BuildDataSystemCePath(user_id)) ||
            !emulated_lock(::BuildDataMiscCePath(user_id)) ||
            !emulated_lock(::BuildDataMediaCePath("", user_id)) ||
            !emulated_lock(::BuildDataUserCePath("", user_id))) {
            LOG(ERROR) << "Failed to lock user " << user_id;
            return false;
        }
    }

    return true;
}

static bool prepare_subdirs(const std::string& action, const std::string& volume_uuid,
                            userid_t user_id, int flags) {
    if (0 != ::ForkExecvp(
                 std::vector<std::string>{prepare_subdirs_path, action, volume_uuid,
                                          std::to_string(user_id), std::to_string(flags)})) {
        LOG(ERROR) << "vold_prepare_subdirs failed";
        return false;
    }
    return true;
}

bool fscrypt_prepare_user_storage(const std::string& volume_uuid, userid_t user_id, int serial,
                                  int flags) {
    LOG(INFO) << "fscrypt_prepare_user_storage for volume " << escape_empty(volume_uuid)
               << ", user " << user_id << ", serial " << serial << ", flags " << flags;

    if (flags & android::os::IVold::STORAGE_FLAG_DE) {
        // DE_sys key
        auto system_legacy_path = ::BuildDataSystemLegacyPath(user_id);
        auto misc_legacy_path = ::BuildDataMiscLegacyPath(user_id);
        auto profiles_de_path = ::BuildDataProfilesDePath(user_id);

        // DE_n key
        auto system_de_path = ::BuildDataSystemDePath(user_id);
        auto misc_de_path = ::BuildDataMiscDePath(user_id);
        auto vendor_de_path = ::BuildDataVendorDePath(user_id);
        auto user_de_path = ::BuildDataUserDePath(volume_uuid, user_id);

        if (volume_uuid.empty()) {
            if (!prepare_dir(system_legacy_path, 0700, AID_SYSTEM, AID_SYSTEM)) return false;
#if MANAGE_MISC_DIRS
            if (!prepare_dir(misc_legacy_path, 0750, multiuser_get_uid(user_id, AID_SYSTEM),
                             multiuser_get_uid(user_id, AID_EVERYBODY)))
                return false;
#endif
            if (!prepare_dir(profiles_de_path, 0771, AID_SYSTEM, AID_SYSTEM)) return false;

            if (!prepare_dir(system_de_path, 0770, AID_SYSTEM, AID_SYSTEM)) return false;
            if (!prepare_dir(misc_de_path, 01771, AID_SYSTEM, AID_MISC)) return false;
            if (!prepare_dir(vendor_de_path, 0771, AID_ROOT, AID_ROOT)) return false;
        }
        if (!prepare_dir(user_de_path, 0771, AID_SYSTEM, AID_SYSTEM)) return false;
        if (fscrypt_is_native()) {
            EncryptionPolicy de_policy;
            if (volume_uuid.empty()) {
                if (!lookup_policy(s_de_policies, user_id, &de_policy)) return false;
                if (!EnsurePolicy(de_policy, system_de_path))
                	LOG(INFO) << "EnsurePolicy returned false for " << system_de_path;
                if (!EnsurePolicy(de_policy, misc_de_path))
                	LOG(INFO) << "EnsurePolicy returned false for " << misc_de_path;
                if (!EnsurePolicy(de_policy, vendor_de_path))
                	LOG(INFO) << "EnsurePolicy returned false for " << vendor_de_path;
            } else {
                if (!read_or_create_volkey(misc_de_path, volume_uuid, &de_policy)) return false;
            }
            if (!EnsurePolicy(de_policy, user_de_path))
            	LOG(INFO) << "EnsurePolicy returned false for " << user_de_path;

        }
    }

    if (flags & android::os::IVold::STORAGE_FLAG_CE) {
        // CE_n key
        auto system_ce_path = ::BuildDataSystemCePath(user_id);
        auto misc_ce_path = ::BuildDataMiscCePath(user_id);
        auto vendor_ce_path = ::BuildDataVendorCePath(user_id);
        auto media_ce_path = ::BuildDataMediaCePath(volume_uuid, user_id);
        auto user_ce_path = ::BuildDataUserCePath(volume_uuid, user_id);

        if (volume_uuid.empty()) {
            if (!prepare_dir(system_ce_path, 0770, AID_SYSTEM, AID_SYSTEM)) return false;
            if (!prepare_dir(misc_ce_path, 01771, AID_SYSTEM, AID_MISC)) return false;
            if (!prepare_dir(vendor_ce_path, 0771, AID_ROOT, AID_ROOT)) return false;
        }
        if (!prepare_dir(media_ce_path, 0770, AID_MEDIA_RW, AID_MEDIA_RW)) return false;

        if (!prepare_dir(user_ce_path, 0771, AID_SYSTEM, AID_SYSTEM)) return false;

        if (fscrypt_is_native()) {
            EncryptionPolicy ce_policy;
            if (volume_uuid.empty()) {
                if (!lookup_policy(s_ce_policies, user_id, &ce_policy)) return false;
                if (!EnsurePolicy(ce_policy, system_ce_path))
                	LOG(INFO) << "EnsurePolicy returned false for " << system_ce_path;
                if (!EnsurePolicy(ce_policy, misc_ce_path))
                	LOG(INFO) << "EnsurePolicy returned false for " << misc_ce_path;
                if (!EnsurePolicy(ce_policy, vendor_ce_path))
                	LOG(INFO) << "EnsurePolicy returned false for " << vendor_ce_path;
            } else {
                if (!read_or_create_volkey(misc_ce_path, volume_uuid, &ce_policy)) return false;
            }
            if (!EnsurePolicy(ce_policy, media_ce_path))
            	LOG(INFO) << "EnsurePolicy returned false for " << media_ce_path;
            if (!EnsurePolicy(ce_policy, user_ce_path))
            	LOG(INFO) << "EnsurePolicy returned false for " << user_ce_path;
        }

        if (volume_uuid.empty()) {
            // Now that credentials have been installed, we can run restorecon
            // over these paths
            // NOTE: these paths need to be kept in sync with libselinux
            ::RestoreconRecursive(system_ce_path);
            ::RestoreconRecursive(vendor_ce_path);
            ::RestoreconRecursive(misc_ce_path);
        }
    }
    if (!prepare_subdirs("prepare", volume_uuid, user_id, flags)) return false;

    return true;
}

bool fscrypt_destroy_user_storage(const std::string& volume_uuid, userid_t user_id, int flags) {
    LOG(INFO) << "fscrypt_destroy_user_storage for volume " << escape_empty(volume_uuid)
               << ", user " << user_id << ", flags " << flags;
    bool res = true;

    res &= prepare_subdirs("destroy", volume_uuid, user_id, flags);

    if (flags & android::os::IVold::STORAGE_FLAG_CE) {
        // CE_n key
        auto system_ce_path = ::BuildDataSystemCePath(user_id);
        auto misc_ce_path = ::BuildDataMiscCePath(user_id);
        auto vendor_ce_path = ::BuildDataVendorCePath(user_id);
        auto media_ce_path = ::BuildDataMediaCePath(volume_uuid, user_id);
        auto user_ce_path = ::BuildDataUserCePath(volume_uuid, user_id);

        res &= destroy_dir(media_ce_path);
        res &= destroy_dir(user_ce_path);
        if (volume_uuid.empty()) {
            res &= destroy_dir(system_ce_path);
            res &= destroy_dir(misc_ce_path);
            res &= destroy_dir(vendor_ce_path);
        } else {
            if (fscrypt_is_native()) {
                res &= destroy_volkey(misc_ce_path, volume_uuid);
            }
        }
    }

    if (flags & android::os::IVold::STORAGE_FLAG_DE) {
        // DE_sys key
        auto system_legacy_path = ::BuildDataSystemLegacyPath(user_id);
        auto misc_legacy_path = ::BuildDataMiscLegacyPath(user_id);
        auto profiles_de_path = ::BuildDataProfilesDePath(user_id);

        // DE_n key
        auto system_de_path = ::BuildDataSystemDePath(user_id);
        auto misc_de_path = ::BuildDataMiscDePath(user_id);
        auto vendor_de_path = ::BuildDataVendorDePath(user_id);
        auto user_de_path = ::BuildDataUserDePath(volume_uuid, user_id);

        res &= destroy_dir(user_de_path);
        if (volume_uuid.empty()) {
            res &= destroy_dir(system_legacy_path);
#if MANAGE_MISC_DIRS
            res &= destroy_dir(misc_legacy_path);
#endif
            res &= destroy_dir(profiles_de_path);
            res &= destroy_dir(system_de_path);
            res &= destroy_dir(misc_de_path);
            res &= destroy_dir(vendor_de_path);
        } else {
            if (fscrypt_is_native()) {
                res &= destroy_volkey(misc_de_path, volume_uuid);
            }
        }
    }

    return res;
}

static bool destroy_volume_keys(const std::string& directory_path, const std::string& volume_uuid) {
    auto dirp = std::unique_ptr<DIR, int (*)(DIR*)>(opendir(directory_path.c_str()), closedir);
    if (!dirp) {
        PLOG(ERROR) << "Unable to open directory: " + directory_path;
        return false;
    }
    bool res = true;
    for (;;) {
        errno = 0;
        auto const entry = readdir(dirp.get());
        if (!entry) {
            if (errno) {
                PLOG(ERROR) << "Unable to read directory: " + directory_path;
                return false;
            }
            break;
        }
        if (entry->d_type != DT_DIR || entry->d_name[0] == '.') {
            LOG(INFO) << "Skipping non-user " << entry->d_name;
            continue;
        }
        res &= destroy_volkey(directory_path + "/" + entry->d_name, volume_uuid);
    }
    return res;
}

bool fscrypt_destroy_volume_keys(const std::string& volume_uuid) {
    bool res = true;
    LOG(INFO) << "fscrypt_destroy_volume_keys for volume " << escape_empty(volume_uuid);
    auto secdiscardable_path = volume_secdiscardable_path(volume_uuid);
    res &= ::runSecdiscardSingle(secdiscardable_path);
    res &= destroy_volume_keys("/data/misc_ce", volume_uuid);
    res &= destroy_volume_keys("/data/misc_de", volume_uuid);
    return res;
}

bool lookup_key_ref(const std::map<userid_t, android::fscrypt::EncryptionPolicy>& key_map, userid_t user_id,
                           std::string* raw_ref) {
    auto refi = key_map.find(user_id);
    if (refi == key_map.end()) {
        LOG(ERROR) << "Cannot find key for " << user_id;
        return false;
    }
    *raw_ref = refi->second.key_raw_ref;
    return true;
}
