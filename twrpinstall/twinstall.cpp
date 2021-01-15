/*
	Copyright 2012 to 2017 bigbiff/Dees_Troy TeamWin
	This file is part of TWRP/TeamWin Recovery Project.

	Copyright 2018 ATG Droid
	This file is part of RWRP/RedWolf Recovery Project

	Copyright 2018-2020 androiabledroid/rezaadipangestu/manjotsidhu
	This file is part of PBRP/PitchBlack Recovery Project

	TWRP is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	TWRP is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with TWRP.	If not, see <http://www.gnu.org/licenses/>.
*/


#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <unistd.h>
#include <iostream>
#include <fstream>

#include <string.h>
#include <stdio.h>
#include <cutils/properties.h>

#include <android-base/unique_fd.h>

#include "twcommon.h"
#include "mtdutils/mounts.h"
#include "mtdutils/mtdutils.h"

#include "otautil/sysutil.h"
#include <ziparchive/zip_archive.h>
#include "twinstall/install.h"
#include "twinstall/verifier.h"
#include "variables.h"
#include "cutils/properties.h"
#include "data.hpp"
#include "partitions.hpp"
#include "twrpDigestDriver.hpp"
#include "twrpDigest/twrpDigest.hpp"
#include "twrpDigest/twrpMD5.hpp"
#include "twrp-functions.hpp"
#include "gui/gui.hpp"
#include "gui/pages.hpp"
#include "legacy_property_service.h"
#include "twinstall.h"
#include "installcommand.h"
extern "C" {
	#include "gui/gui.h"
}

#define AB_OTA "payload_properties.txt"
#define OTA_CORRUPT "INSTALL_CORRUPT"
#define OTA_ERROR "INSTALL_ERROR"
#define OTA_VERIFY_FAIL "INSTALL_VERIFY_FAILURE"
#define OTA_SUCCESS "INSTALL_SUCCESS"
bool trb_en = false;

#ifndef TW_NO_LEGACY_PROPS
static const char* properties_path = "/dev/__properties__";
static const char* properties_path_renamed = "/dev/__properties_kk__";
static bool legacy_props_env_initd = false;
static bool legacy_props_path_modified = false;
#endif

enum zip_type {
	UNKNOWN_ZIP_TYPE = 0,
	UPDATE_BINARY_ZIP_TYPE,
	AB_OTA_ZIP_TYPE,
	TWRP_THEME_ZIP_TYPE
};

#ifndef TW_NO_LEGACY_PROPS
// to support pre-KitKat update-binaries that expect properties in the legacy format
static int switch_to_legacy_properties()
{
	if (!legacy_props_env_initd) {
		if (legacy_properties_init() != 0)
			return -1;

		char tmp[32];
		int propfd, propsz;
		legacy_get_property_workspace(&propfd, &propsz);
		sprintf(tmp, "%d,%d", dup(propfd), propsz);
		setenv("ANDROID_PROPERTY_WORKSPACE", tmp, 1);
		legacy_props_env_initd = true;
	}

	if (TWFunc::Path_Exists(properties_path)) {
		// hide real properties so that the updater uses the envvar to find the legacy format properties
		if (rename(properties_path, properties_path_renamed) != 0) {
			LOGERR("Renaming %s failed: %s\n", properties_path, strerror(errno));
			return -1;
		} else {
			legacy_props_path_modified = true;
		}
	}

	return 0;
}

static int switch_to_new_properties()
{
	if (TWFunc::Path_Exists(properties_path_renamed)) {
		if (rename(properties_path_renamed, properties_path) != 0) {
			LOGERR("Renaming %s failed: %s\n", properties_path_renamed, strerror(errno));
			return -1;
		} else {
			legacy_props_path_modified = false;
		}
	}

	return 0;
}
#endif

static int Install_Theme(const char* path, ZipArchiveHandle Zip) {
#ifdef TW_OEM_BUILD // We don't do custom themes in OEM builds
	CloseArchive(Zip);
	return INSTALL_CORRUPT;
#else
	ZipString binary_name("ui.xml");
	ZipEntry binary_entry;
	if (FindEntry(Zip, binary_name, &binary_entry) != 0) {
		CloseArchive(Zip);
		return INSTALL_CORRUPT;
	}
	if (!PartitionManager.Mount_Settings_Storage(true))
		return INSTALL_ERROR;
	string theme_path = DataManager::GetSettingsStoragePath();
	theme_path += "/PBRP/theme";
	if (!TWFunc::Path_Exists(theme_path)) {
		if (!TWFunc::Recursive_Mkdir(theme_path)) {
			return INSTALL_ERROR;
		}
	}
	theme_path += "/ui.zip";
	if (TWFunc::copy_file(path, theme_path, 0644) != 0) {
		return INSTALL_ERROR;
	}
	LOGINFO("Installing custom theme '%s' to '%s'\n", path, theme_path.c_str());
	PageManager::RequestReload();
	return INSTALL_SUCCESS;
#endif
}

static void Write_MIUI_Install_Status(std::string install_status, bool verify) {
if (DataManager::GetStrValue("tw_action") == "openrecoveryscript") {
std::string last_status = "/cache/recovery/last_status";
if (!PartitionManager.Mount_By_Path("/cache", true))
return;
if (!verify) {
if (DataManager::GetIntValue(PB_MIUI_ZIP_TMP) != 0 || DataManager::GetIntValue(PB_METADATA_PRE_BUILD) != 0 || trb_en) {
		if (TWFunc::Path_Exists(last_status))
		unlink(last_status.c_str());
		
		 ofstream status;
		 status.open (last_status.c_str());
		 status << install_status;
		 status.close();
		 chmod(last_status.c_str(), 0755);
		}
	 } else {
		if (TWFunc::Path_Exists(last_status))
		unlink(last_status.c_str());
		
		 ofstream status;
		 status.open (last_status.c_str());
		 status << install_status;
		 status.close();
		 chmod(last_status.c_str(), 0755);
		 }
	 }
}

static int Prepare_Update_Binary(ZipArchiveHandle Zip) {
	string pre_something = "pre-";
	string miui_update = "_update";
	string meta = "META-INF/com";
	string metadata = "/android/metadata";
	string miui_word = "/miui";
	string miui_sg_path = meta + miui_word + miui_word + miui_update;
	string metadata_sg_path = meta + metadata;
	string fingerprint_property = "ro.build.fingerprint";
	string pre_device = pre_something + "device";
	string pre_build = pre_something + "build";
	int chk_sdk = 26 ;

	char arches[PATH_MAX];
	property_get("ro.product.cpu.abilist", arches, "error");
	if (strcmp(arches, "error") == 0)
	property_get("ro.product.cpu.abi", arches, "error");
	vector<string> split = TWFunc::split_string(arches, ',', true);
	std::vector<string>::iterator arch;
	std::string base_name = UPDATE_BINARY_NAME;
	base_name += "-";
	ZipEntry binary_entry;
	ZipString update_binary_string(UPDATE_BINARY_NAME);
	if (FindEntry(Zip, update_binary_string, &binary_entry) != 0) {
		for (arch = split.begin(); arch != split.end(); arch++) {
			std::string temp = base_name + *arch;
			ZipString binary_name(temp.c_str());
			if (FindEntry(Zip, binary_name, &binary_entry) != 0) {
				ZipString binary_name(temp.c_str());
				break;
			}
		}
	}
	LOGINFO("Extracting updater binary '%s'\n", UPDATE_BINARY_NAME);
	unlink(TMP_UPDATER_BINARY_PATH);
	android::base::unique_fd fd(
		open(TMP_UPDATER_BINARY_PATH, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0755));
	if (fd == -1) {
		return INSTALL_ERROR;
	}
	int32_t err = ExtractEntryToFile(Zip, &binary_entry, fd);
	if (err != 0) {
		CloseArchive(Zip);
		LOGERR("Could not extract '%s'\n", UPDATE_BINARY_NAME);
		return INSTALL_ERROR;
	}

	if (DataManager::GetIntValue(PB_INSTALL_PREBUILT_ZIP) != 1) {
		DataManager::SetValue(PB_METADATA_PRE_BUILD, 0);
		DataManager::SetValue(PB_MIUI_ZIP_TMP, 0);
		DataManager::SetValue(PB_RUN_SURVIVAL_BACKUP, 0);
		DataManager::SetValue(PB_INCREMENTAL_OTA_FAIL, 0);
		DataManager::SetValue(PB_LOADED_FINGERPRINT, 0);

		gui_msg("pb_install_detecting=Detecting Current Package");

		ZipString miui_sg(miui_sg_path.c_str());
		ZipString system_br("system.new.dat");
		ZipString system_("system.new.dat.br");
		ZipString vendor_br("vendor.new.dat.br");
		ZipString vendor_("vendor.new.dat");
		ZipString bootimg("boot.img");
		ZipEntry miui_sg_entry;
		int update_data[] = {FindEntry(Zip, miui_sg, &miui_sg_entry),
					FindEntry(Zip, system_, nullptr),
					FindEntry(Zip, system_br, nullptr),
					FindEntry(Zip, vendor_, nullptr),
					FindEntry(Zip, vendor_br, nullptr),
					FindEntry(Zip, bootimg, nullptr)
				};
		string outp = TWFunc::Get_output("grep miui.ui.version " + std::string(TMP_UPDATER_BINARY_PATH));
		if (!update_data[3] || !update_data[4])
		{
			chk_sdk = 27;
			DataManager::SetValue(TRB_EN, 1);
		}
		else
			chk_sdk = 26;
		if ((outp.size() > 0 || !update_data[0]) && chk_sdk < 27) {
			if (!update_data[1] || !update_data[2]) {
				DataManager::SetValue(PB_MIUI_ZIP_TMP, 1);
			}
			DataManager::SetValue(PB_CALL_DEACTIVATION, 1);
			DataManager::SetValue(NON_STD, 1);
			if (!update_data[0]) {
				gui_msg("pb_install_miui_detected=- Detected Standard MIUI Update Package");
			}
			else
				gui_msg("pb_install_miui_10_detected=- Detected MIUI 10 Non-Treble Update Package");
		} else {
			if (outp.size() > 0 && chk_sdk >= 27) {
				DataManager::SetValue(PB_MIUI_ZIP_TMP, 1);
				DataManager::SetValue(PB_CALL_DEACTIVATION, 1);
				trb_en = true;
				gui_msg("pb_install_miui_oreo_detected=- Detected Treble MIUI Update Package");
			}
			else if (!update_data[1] || !update_data[2]) {
				DataManager::SetValue(PB_CALL_DEACTIVATION, 1);
				DataManager::SetValue(STD, "1");
				gui_msg("pb_install_standard_detected=- Detected standard Package");
			}
			else {
				if (!update_data[3]) {
						DataManager::SetValue(PB_CALL_DEACTIVATION, 1);
				}
				gui_msg("pb_install_patch_detected=- Detected Either a Patch or Fix Package");
			}
		}

		if (DataManager::GetIntValue(PB_INCREMENTAL_PACKAGE) != 0) {
			gui_msg("pb_incremental_ota_status_enabled=Support MIUI Incremental package status: Enabled");
			if (!update_data[0]) {
				android::base::unique_fd take_out_metadata(
							open("/tmp/build.prop", O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644));
				if (ExtractEntryToFile(Zip, &miui_sg_entry, take_out_metadata)) {
					string metadata_fingerprint = TWFunc::File_Property_Get("/tmp/build.prop", pre_build);
					string metadata_device = TWFunc::File_Property_Get("/tmp/build.prop", pre_device);
					string fingerprint = TWFunc::System_Property_Get(fingerprint_property);
					if (!metadata_fingerprint.empty() && metadata_fingerprint.size() > PB_MIN_EXPECTED_FP_SIZE) {
//						gui_msg(Msg("pb_incremental_package_detected=Detected Incremental package '{1}'")(path));
						DataManager::SetValue(PB_METADATA_PRE_BUILD, 1);
						if (!fingerprint.empty() && fingerprint.size() > PB_MIN_EXPECTED_FP_SIZE && DataManager::GetIntValue("pb_verify_incremental_ota_signature") != 0) {
							gui_msg("pb_incremental_ota_compatibility_chk=Verifying Incremental Package Signature...");
							if (TWFunc::Verify_Incremental_Package(fingerprint, metadata_fingerprint, metadata_device)) {
								gui_msg("pb_incremental_ota_compatibility_true=Incremental package is compatible.");
								TWFunc::Property_Override(fingerprint_property.c_str(), metadata_fingerprint.c_str());
								DataManager::SetValue(PB_LOADED_FINGERPRINT, metadata_fingerprint);
							} else {
								Write_MIUI_Install_Status(OTA_VERIFY_FAIL, false);
								gui_err("pb_incremental_ota_compatibility_false=Incremental package isn't compatible with this ROM!");
								return INSTALL_ERROR;
							}
						} else {
							TWFunc::Property_Override(fingerprint_property.c_str(), metadata_fingerprint.c_str());
						}
						unlink("/tmp/build.prop");
					}
				} else {
					CloseArchive(Zip);
					LOGINFO("Could not extract Metadata\n");
					Write_MIUI_Install_Status(OTA_ERROR, false);
					return INSTALL_ERROR;
				}
			}
		} else {
			gui_msg("pb_incremental_ota_status_disabled=Support MIUI Incremental package status: Disabled");
		}

		string ota_location_folder, ota_location_backup, loadedfp;
		DataManager::GetValue(PB_SURVIVAL_FOLDER_VAR, ota_location_folder);
		DataManager::GetValue(PB_SURVIVAL_BACKUP_NAME, ota_location_backup);
		ota_location_folder += "/" + ota_location_backup;
		DataManager::GetValue(PB_LOADED_FINGERPRINT, loadedfp);
		string Boot_File = ota_location_folder + "/boot.emmc.win";

		if (DataManager::GetIntValue(PB_METADATA_PRE_BUILD) != 0 && !TWFunc::Verify_Loaded_OTA_Signature(loadedfp, ota_location_folder)) {
			TWPartition * survival_boot = PartitionManager.Find_Partition_By_Path("/boot");

			if (!survival_boot) {
				Write_MIUI_Install_Status(OTA_ERROR, false);
				LOGERR("OTA_Survival: Boot issue");
				return INSTALL_ERROR;
			}

			std::string action;
			DataManager::GetValue("tw_action", action);
			if (action != "openrecoveryscript" && DataManager::GetIntValue(PB_MIUI_ZIP_TMP) != 0) {
				LOGERR("Please flash this package using MIUI updater app!");
				return INSTALL_ERROR;
			}

			if (DataManager::GetIntValue(TW_IS_ENCRYPTED) == 0) {
				if (TWFunc::Path_Exists(Boot_File)) {
					gui_msg("pb_incremental_ota_res_run=Running restore process of the current OTA file");
					DataManager::SetValue(PB_RUN_SURVIVAL_BACKUP, 1);
					PartitionManager.Set_Restore_Files(ota_location_folder);
					if (PartitionManager.Run_OTA_Survival_Restore(ota_location_folder)) {
						gui_msg("pb_incremental_ota_res=Process OTA_RES -- done!!");
					} else {
						Write_MIUI_Install_Status(OTA_ERROR, false);
						LOGERR("OTA_Survival: Unable to finish OTA_RES!\n");
						return INSTALL_ERROR;
					}
				} else {
					Write_MIUI_Install_Status(OTA_CORRUPT, false);
					gui_err("pb_survival_does_not_exist=OTA Survival does not exist! Please flash a full ROM first!");
					return INSTALL_ERROR;
				}
			} else {
				Write_MIUI_Install_Status(OTA_CORRUPT, false);
				gui_err("pb_survival_encrypted_err=Internal storage is encrypted! Please do decrypt first!");
				return INSTALL_ERROR;
			}
		}
	}
	// If exists, extract file_contexts from the zip file
	ZipString file_contexts("file_contexts");
	ZipEntry file_contexts_entry;
	if (FindEntry(Zip, file_contexts, &file_contexts_entry) != 0) {
		LOGINFO("Zip does not contain SELinux file_contexts file in its root.\n");
	} else {
		const string output_filename = "/file_contexts";
		LOGINFO("Zip contains SELinux file_contexts file in its root. Extracting to %s\n", output_filename.c_str());
		android::base::unique_fd fd(
			open(output_filename.c_str(), O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644));
		if (fd == -1) {
			return INSTALL_ERROR;
		}
		if (ExtractEntryToFile(Zip, &file_contexts_entry, fd)) {
			CloseArchive(Zip);
			Write_MIUI_Install_Status(OTA_CORRUPT, false);
			LOGERR("Could not extract '%s'\n", output_filename.c_str());
			return INSTALL_ERROR;
		}
	}
	return INSTALL_SUCCESS;
}

#ifndef TW_NO_LEGACY_PROPS
static bool update_binary_has_legacy_properties(const char *binary) {
	const char str_to_match[] = "ANDROID_PROPERTY_WORKSPACE";
	int len_to_match = sizeof(str_to_match) - 1;
	bool found = false;

	int fd = open(binary, O_RDONLY);
	if (fd < 0) {
		LOGINFO("has_legacy_properties: Could not open %s: %s!\n", binary, strerror(errno));
		return false;
	}

	struct stat finfo;
	if (fstat(fd, &finfo) < 0) {
		LOGINFO("has_legacy_properties: Could not fstat %d: %s!\n", fd, strerror(errno));
		close(fd);
		return false;
	}

	void *data = mmap(NULL, finfo.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (data == MAP_FAILED) {
		LOGINFO("has_legacy_properties: mmap (size=%zu) failed: %s!\n", (size_t)finfo.st_size, strerror(errno));
	} else {
		if (memmem(data, finfo.st_size, str_to_match, len_to_match)) {
			LOGINFO("has_legacy_properties: Found legacy property match!\n");
			found = true;
		}
		munmap(data, finfo.st_size);
	}
	close(fd);

	return found;
}
#endif

static int Run_Update_Binary(const char *path, int* wipe_cache, zip_type ztype) {
	int ret_val, pipe_fd[2], status, zip_verify;
	char buffer[1024];
	FILE* child_data;

#ifndef TW_NO_LEGACY_PROPS
	if (!update_binary_has_legacy_properties(TMP_UPDATER_BINARY_PATH)) {
		LOGINFO("Legacy property environment not used in updater.\n");
	} else if (switch_to_legacy_properties() != 0) { /* Set legacy properties */
		LOGERR("Legacy property environment did not initialize successfully. Properties may not be detected.\n");
	} else {
		LOGINFO("Legacy property environment initialized.\n");
	}
#endif

	pipe(pipe_fd);

	std::vector<std::string> args;
		if (ztype == UPDATE_BINARY_ZIP_TYPE) {
		ret_val = update_binary_command(path, 0, pipe_fd[1], &args);
		} else if (ztype == AB_OTA_ZIP_TYPE) {
		ret_val = abupdate_binary_command(path, 0, pipe_fd[1], &args);
	} else {
		LOGERR("Unknown zip type %i\n", ztype);
		ret_val = INSTALL_CORRUPT;
	}
		if (ret_val) {
				close(pipe_fd[0]);
				close(pipe_fd[1]);
				return ret_val;
		}

	// Convert the vector to a NULL-terminated char* array suitable for execv.
	const char* chr_args[args.size() + 1];
	chr_args[args.size()] = NULL;
	for (size_t i = 0; i < args.size(); i++)
		chr_args[i] = args[i].c_str();

	pid_t pid = fork();
	if (pid == 0) {
		close(pipe_fd[0]);
		execve(chr_args[0], const_cast<char**>(chr_args), environ);
		printf("E:Can't execute '%s': %s\n", chr_args[0], strerror(errno));
		_exit(-1);
	}
	close(pipe_fd[1]);

	*wipe_cache = 0;

	DataManager::GetValue(TW_SIGNED_ZIP_VERIFY_VAR, zip_verify);
	child_data = fdopen(pipe_fd[0], "r");
	while (fgets(buffer, sizeof(buffer), child_data) != NULL) {
		char* command = strtok(buffer, " \n");
		if (command == NULL) {
			continue;
		} else if (strcmp(command, "progress") == 0) {
			char* fraction_char = strtok(NULL, " \n");
			char* seconds_char = strtok(NULL, " \n");

			float fraction_float = strtof(fraction_char, NULL);
			int seconds_float = strtol(seconds_char, NULL, 10);

			if (zip_verify)
				DataManager::ShowProgress(fraction_float * (1 - VERIFICATION_PROGRESS_FRACTION), seconds_float);
			else
				DataManager::ShowProgress(fraction_float, seconds_float);
		} else if (strcmp(command, "set_progress") == 0) {
			char* fraction_char = strtok(NULL, " \n");
			float fraction_float = strtof(fraction_char, NULL);
			DataManager::_SetProgress(fraction_float);
		} else if (strcmp(command, "ui_print") == 0) {
			char* display_value = strtok(NULL, "\n");
			if (display_value) {
				gui_print("%s", display_value);
			} else {
				gui_print("\n");
			}
		} else if (strcmp(command, "wipe_cache") == 0) {
			*wipe_cache = 1;
		} else if (strcmp(command, "clear_display") == 0) {
			// Do nothing, not supported by TWRP
		} else if (strcmp(command, "log") == 0) {
			printf("%s\n", strtok(NULL, "\n"));
		} else {
			LOGERR("unknown command [%s]\n", command);
		}
	}
	fclose(child_data);

	int waitrc = TWFunc::Wait_For_Child(pid, &status, "Updater");

	if (WEXITSTATUS(status) == 7)
		gui_err("assert_failed_hint=An assert failed. Please check the output above for more details.");

#ifndef TW_NO_LEGACY_PROPS
	/* Unset legacy properties */
	if (legacy_props_path_modified) {
		if (switch_to_new_properties() != 0) {
			LOGERR("Legacy property environment did not disable successfully. Legacy properties may still be in use.\n");
		} else {
			LOGINFO("Legacy property environment disabled.\n");
		}
	}
#endif

	if (waitrc != 0) {
		Write_MIUI_Install_Status(OTA_CORRUPT, false);
		return INSTALL_ERROR;
				}

	return INSTALL_SUCCESS;
}

int TWinstall_zip(const char* path, int* wipe_cache) {
	int ret_val, zip_verify = 1;

	if (strcmp(path, "error") == 0) {
		LOGERR("Failed to get adb sideload file: '%s'\n", path);
		return INSTALL_CORRUPT;
	}



		if (DataManager::GetIntValue(PB_INSTALL_PREBUILT_ZIP) != 1) {

	/* First delink all our symlinks to /system, coz we donno the behaviour of the flashing zip */
	if (PartitionManager.Is_Mounted_By_Path("/system_root") || TWFunc::Path_Exists("/system/system"))
	{
		string UM ="/system";
		umount(UM.c_str());
	}
	gui_msg(Msg("installing_zip=Installing zip file '{1}'")(path));
	if (strlen(path) < 9 || strncmp(path, "/sideload", 9) != 0) {
		string digest_str;
		string Full_Filename = path;

		gui_msg("check_for_digest=Checking for Digest file...");

		if (*path != '@' && !twrpDigestDriver::Check_File_Digest(Full_Filename)) {
			LOGERR("Aborting zip install: Digest verification failed\n");
			Write_MIUI_Install_Status(OTA_CORRUPT, true);
			return INSTALL_CORRUPT;
		}
	}
	}

#ifndef TW_OEM_BUILD
	DataManager::GetValue(TW_SIGNED_ZIP_VERIFY_VAR, zip_verify);
#endif
	DataManager::SetProgress(0);

	auto package = Package::CreateMemoryPackage(path);
	if (!package) {
		return INSTALL_CORRUPT;
	}

	if (zip_verify) {
		gui_msg("verify_zip_sig=Verifying zip signature...");
		static constexpr const char* CERTIFICATE_ZIP_FILE = "/system/etc/security/otacerts.zip";
		std::vector<Certificate> loaded_keys = LoadKeysFromZipfile(CERTIFICATE_ZIP_FILE);
		if (loaded_keys.empty()) {
			LOGINFO("Failed to load keys");
			gui_err("verify_zip_fail=Zip signature verification failed!");
			Write_MIUI_Install_Status(OTA_VERIFY_FAIL, true);
			return -1;
		}
		LOGINFO("%zu key(s) loaded from %s\n", loaded_keys.size(), CERTIFICATE_ZIP_FILE);

		ret_val = verify_file(package.get(), loaded_keys, std::bind(&DataManager::SetProgress, std::placeholders::_1));
		if (ret_val != VERIFY_SUCCESS) {
			LOGINFO("Zip signature verification failed: %i\n", ret_val);
			gui_err("verify_zip_fail=Zip signature verification failed!");
			Write_MIUI_Install_Status(OTA_VERIFY_FAIL, true);
#ifdef USE_MINZIP
			sysReleaseMap(&map);
#endif
			return -1;
		} else {
			gui_msg("verify_zip_done=Zip signature verified successfully.");
		}
	}
	ZipArchiveHandle Zip = package->GetZipArchiveHandle();;
	if (!Zip) {
		Write_MIUI_Install_Status(OTA_CORRUPT, true);
		gui_err("zip_corrupt=Zip file is corrupt!");
		return INSTALL_CORRUPT;
	}

	time_t start, stop;
	time(&start);

	ZipString update_binary_name(UPDATE_BINARY_NAME);
	ZipEntry update_binary_entry;
	if (FindEntry(Zip, update_binary_name, &update_binary_entry) == 0) {
		LOGINFO("Update binary zip\n");
		// Additionally verify the compatibility of the package.
		if (!verify_package_compatibility(Zip) && DataManager::GetIntValue(PB_TREBLE_COMP) == 0) {
			gui_err("zip_compatible_err=Zip Treble compatibility error!");
			CloseArchive(Zip);
			ret_val = INSTALL_CORRUPT;
		} else {
			ret_val = Prepare_Update_Binary(Zip);
			if (ret_val == INSTALL_SUCCESS)
				ret_val = Run_Update_Binary(path, wipe_cache, UPDATE_BINARY_ZIP_TYPE);
				else
				DataManager::SetValue(PB_INCREMENTAL_OTA_FAIL, 1);
				if (ret_val != INSTALL_SUCCESS)
					 DataManager::SetValue(PB_INCREMENTAL_OTA_FAIL, 1);
		}
	} else {
		ZipString ab_binary_name(AB_OTA);
		ZipEntry ab_binary_entry;
		if (FindEntry(Zip, ab_binary_name, &ab_binary_entry) == 0) {
			LOGINFO("AB zip\n");
			// We need this so backuptool can do its magic
			bool system_mount_state = PartitionManager.Is_Mounted_By_Path(PartitionManager.Get_Android_Root_Path());
			bool vendor_mount_state = PartitionManager.Is_Mounted_By_Path("/vendor");
			PartitionManager.Mount_By_Path(PartitionManager.Get_Android_Root_Path(), true);
			PartitionManager.Mount_By_Path("/vendor", true);
			TWFunc::copy_file("/sbin/sh", "/tmp/sh", 0755);
			mount("/tmp/sh", "/system/bin/sh", "auto", MS_BIND, NULL);
			gui_msg(Msg(msg::kHighlight, "flash_ab_inactive=Flashing A/B zip to inactive slot: {1}")(PartitionManager.Get_Active_Slot_Display()=="A"?"B":"A"));
			ret_val = Run_Update_Binary(path, wipe_cache, AB_OTA_ZIP_TYPE);
			umount("/system/bin/sh");
			unlink("/tmp/sh");
			if (!vendor_mount_state)
				PartitionManager.UnMount_By_Path("/vendor", true);
			if (!system_mount_state)
				PartitionManager.UnMount_By_Path(PartitionManager.Get_Android_Root_Path(), true);
			gui_warn("flash_ab_reboot=To flash additional zips, please reboot recovery to switch to the updated slot.");
		} else {
			ZipString binary_name("ui.xml");
			ZipEntry binary_entry;
			if (FindEntry(Zip, binary_name, &binary_entry) != 0) {
				LOGINFO("PBRP theme zip\n");
				ret_val = Install_Theme(path, Zip);
			} else {
				CloseArchive(Zip);
				ret_val = INSTALL_CORRUPT;
			}
		}
	}
	time(&stop);
	int total_time = (int) difftime(stop, start);
	if (ret_val == INSTALL_CORRUPT) {
		Write_MIUI_Install_Status(OTA_CORRUPT, true);
		gui_err("invalid_zip_format=Invalid zip file format!");
				 } else {
			if ((DataManager::GetIntValue(PB_MIUI_ZIP_TMP) != 0 && DataManager::GetIntValue(PB_INCREMENTAL_OTA_FAIL) != 1) || (DataManager::GetIntValue(PB_METADATA_PRE_BUILD) != 0 && DataManager::GetIntValue(PB_INCREMENTAL_OTA_FAIL) != 1))	{
		DataManager::SetValue(PB_DO_SYSTEM_ON_OTA, 0);
		string ota_folder, ota_backup, loadedfp;
		DataManager::GetValue(PB_SURVIVAL_FOLDER_VAR, ota_folder);
		DataManager::GetValue(PB_SURVIVAL_BACKUP_NAME, ota_backup);
		DataManager::GetValue(PB_LOADED_FINGERPRINT, loadedfp);
		ota_folder += "/" + ota_backup;
		string ota_info = ota_folder + "/pb.info";
		if (TWFunc::Verify_Loaded_OTA_Signature(loadedfp, ota_folder)) {
		gui_msg("pb_incremental_ota_bak_skip=Detected OTA survival with the same ID - leaving");
		} else {
		if (TWFunc::Path_Exists(ota_folder))
		TWFunc::removeDir(ota_folder, false);
	
		DataManager::SetValue(PB_RUN_SURVIVAL_BACKUP, 1);
				gui_msg("pb_incremental_ota_bak_run=Running OTA_BAK process...");
		PartitionManager.Run_OTA_Survival_Backup(false);
		Write_MIUI_Install_Status(OTA_SUCCESS, false);
		gui_msg("pb_incremental_ota_bak=Process OTA_BAK --- done!");	
		if (TWFunc::Path_Exists(ota_folder) && !TWFunc::Path_Exists(ota_info)) {
				TWFunc::create_fingerprint_file(ota_info, loadedfp);
									}
			 }
		 }
				if (ret_val == INSTALL_SUCCESS)
			Write_MIUI_Install_Status(OTA_SUCCESS, false);
			if (ret_val == INSTALL_ERROR)
				Write_MIUI_Install_Status(OTA_ERROR, false);
				DataManager::SetValue(PB_METADATA_PRE_BUILD, 0);
					DataManager::SetValue(PB_MIUI_ZIP_TMP, 0);					
					DataManager::SetValue(PB_RUN_SURVIVAL_BACKUP, 0);
					DataManager::SetValue(PB_INCREMENTAL_OTA_FAIL, 0);
					DataManager::SetValue(PB_LOADED_FINGERPRINT, 0);
				LOGINFO("Install took %i second(s).\n", total_time);
	}
	return ret_val;
}
