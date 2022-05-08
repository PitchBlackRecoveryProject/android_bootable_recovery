/*
		Copyright 2018 ATG Droid  
		This file is part of RWRP/RedWolf Recovery Project

		TWRP is free software: you can redistribute it and/or modify
		it under the terms of the GNU General Public License as published by
		the Free Software Foundation, either version 3 of the License, or
		(at your option) any later version.

		TWRP is distributed in the hope that it will be useful,
		but WITHOUT ANY WARRANTY; without even the implied warranty of
		MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
		GNU General Public License for more details.

		You should have received a copy of the GNU General Public License
		along with TWRP.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include "gui/twmsg.h"

#include "cutils/properties.h"

#ifdef ANDROID_RB_RESTART
#include "cutils/android_reboot.h"
#else
#include <sys/reboot.h>
#endif

extern "C" {
#include "gui/gui.h"
}
#include "set_metadata.h"
#include "gui/gui.hpp"
#include "gui/pages.hpp"
#include "gui/objects.hpp"
#include "twcommon.h"
#include "twrp-functions.hpp"
#include "data.hpp"
#include "partitions.hpp"
#ifdef __ANDROID_API_N__
#include <android-base/strings.h>
#else
#include <base/strings.h>
#endif
#include "openrecoveryscript.hpp"
#include "variables.h"
#include "startupArgs.hpp"
#include "twrpAdbBuFifo.hpp"
#ifdef TW_USE_NEW_MINADBD
// #include "minadbd/minadbd.h"
#else
extern "C" {
#include "minadbd21/adb.h"
}
#endif

//extern int adb_server_main(int is_daemon, int server_port, int /* reply_fd */);

TWPartitionManager PartitionManager;
int Log_Offset;
bool datamedia;

static void Print_Prop(const char *key, const char *name, void *cookie) {
	printf("%s=%s\n", key, name);
}

static void Decrypt_Page(bool SkipDecryption, bool datamedia) {
	// Offer to decrypt if the device is encrypted
	if (DataManager::GetIntValue(TW_IS_ENCRYPTED) != 0) {
		if (SkipDecryption) {
			LOGINFO("Skipping decryption\n");
		} else if (DataManager::GetIntValue(TW_CRYPTO_PWTYPE) != 0) {
			LOGINFO("Is encrypted, do decrypt page first\n");
			if (DataManager::GetIntValue(TW_IS_FBE))
				DataManager::SetValue("tw_crypto_user_id", "0");
			if (gui_startPage("decrypt", 1, 1) != 0) {
				LOGERR("Failed to start decrypt GUI page.\n");
			} else {
				// Check for and load custom theme if present
				TWFunc::check_selinux_support();
				gui_loadCustomResources();
			}
		}
	} else if (datamedia) {
		TWFunc::check_selinux_support();
		if (tw_get_default_metadata(DataManager::GetSettingsStoragePath().c_str()) != 0) {
			LOGINFO("Failed to get default contexts and file mode for storage files.\n");
		} else {
			LOGINFO("Got default contexts and file mode for storage files.\n");
		}
	}
}

static void process_recovery_mode(twrpAdbBuFifo* adb_bu_fifo, bool skip_decryption) {
	char crash_prop_val[PROPERTY_VALUE_MAX];
	int crash_counter;
	property_get("twrp.crash_counter", crash_prop_val, "-1");
	crash_counter = atoi(crash_prop_val) + 1;
	snprintf(crash_prop_val, sizeof(crash_prop_val), "%d", crash_counter);
	property_set("twrp.crash_counter", crash_prop_val);

	printf("=> Linking mtab\n");
	symlink("/proc/mounts", "/etc/mtab");
	std::string fstab_filename = "/etc/twrp.fstab";
	if (!TWFunc::Path_Exists(fstab_filename)) {
		fstab_filename = "/system/etc/recovery.fstab";
		if (!TWFunc::Path_Exists(fstab_filename))
			fstab_filename = "/etc/recovery.fstab";
	}

	// Begin SAR detection
	{
		TWPartitionManager SarPartitionManager;
		printf("=> Processing %s for SAR-detection\n", fstab_filename.c_str());
		if (!SarPartitionManager.Process_Fstab(fstab_filename, 1, 1)) {
			LOGERR("Failing out of recovery due to problem with fstab.\n");
			return;
		}

		mkdir("/s", 0755);

#if defined(AB_OTA_UPDATER) || defined(__ANDROID_API_Q__)
		bool fallback_sar = true;
#else
		bool fallback_sar = property_get_bool("ro.build.system_root_image", false);
#endif

		if(SarPartitionManager.Mount_By_Path("/s", false)) {
			if (TWFunc::Path_Exists("/s/build.prop")) {
				LOGINFO("SAR-DETECT: Non-SAR System detected\n");
				property_set("ro.twrp.sar", "0");
				rmdir("/system_root");
			} else if (TWFunc::Path_Exists("/s/system/build.prop")) {
				LOGINFO("SAR-DETECT: SAR System detected\n");
				property_set("ro.twrp.sar", "1");
			} else {
				LOGINFO("SAR-DETECT: No build.prop found, falling back to %s\n", fallback_sar ? "SAR" : "Non-SAR");
				property_set("ro.twrp.sar", fallback_sar ? "1" : "0");
			}

			SarPartitionManager.UnMount_By_Path("/s", false);
		} else {
			LOGINFO("SAR-DETECT: Could not mount system partition, falling back to %s\n", fallback_sar ? "SAR":"Non-SAR");
			property_set("ro.twrp.sar", fallback_sar ? "1" : "0");
		}

		rmdir("/s");

		TWFunc::check_and_run_script("/system/bin/sarsetup.sh", "boot");
	}
	// End SAR detection

	printf("=> Processing %s\n", fstab_filename.c_str());
	if (!PartitionManager.Process_Fstab(fstab_filename, 1, 0)) {
		LOGERR("Failing out of recovery due to problem with fstab.\n");
		return;
	}

	PartitionManager.Output_Partition_Logging();

// We are doing this here to allow super partition to be set up prior to overriding properties
#if defined(TW_INCLUDE_LIBRESETPROP) && defined(TW_OVERRIDE_SYSTEM_PROPS)
	if (!PartitionManager.Mount_By_Path(PartitionManager.Get_Android_Root_Path(), true)) {
		LOGERR("Unable to mount %s\n", PartitionManager.Get_Android_Root_Path().c_str());
	} else {
		stringstream override_props(EXPAND(TW_OVERRIDE_SYSTEM_PROPS));
		string current_prop;
		while (getline(override_props, current_prop, ';')) {
			string other_prop;
			if (current_prop.find("=") != string::npos) {
				other_prop = current_prop.substr(current_prop.find("=") + 1);
				current_prop = current_prop.substr(0, current_prop.find("="));
			} else {
				other_prop = current_prop;
			}
			other_prop = android::base::Trim(other_prop);
			current_prop = android::base::Trim(current_prop);
			string sys_val = TWFunc::System_Property_Get(other_prop, PartitionManager, PartitionManager.Get_Android_Root_Path().c_str());
			if (!sys_val.empty()) {
				LOGINFO("Overriding %s with value: \"%s\" from system property %s\n", current_prop.c_str(), sys_val.c_str(), other_prop.c_str());
				int error = TWFunc::Property_Override(current_prop, sys_val);
				if (error) {
					LOGERR("Failed overriding property %s, error_code: %d\n", current_prop.c_str(), error);
				}
			} else {
				LOGINFO("Not overriding %s with empty value from system property %s\n", current_prop.c_str(), other_prop.c_str());
			}
		}
		PartitionManager.UnMount_By_Path(PartitionManager.Get_Android_Root_Path(), false);
	}
#endif

	// Check for and run startup script if script exists
	TWFunc::check_and_run_script("/system/bin/runatboot.sh", "boot");
	TWFunc::check_and_run_script("/system/bin/postrecoveryboot.sh", "boot"); 

	if (crash_counter == 0) {
		property_list(Print_Prop, NULL);
		printf("\n");
	} else {
		printf("twrp.crash_counter=%d\n", crash_counter);
	}


	Decrypt_Page(skip_decryption, datamedia);

	// Fixup the RTC clock on devices which require it
	if (crash_counter == 0)
		TWFunc::Fixup_Time_On_Boot();

	DataManager::ReadSettingsFile();

	// Run any outstanding OpenRecoveryScript
	std::string cacheDir = TWFunc::get_log_dir();
	if (cacheDir == DATA_LOGS_DIR)
		cacheDir = "/data/cache";
	std::string orsFile = cacheDir + "/recovery/openrecoveryscript";
	if ((DataManager::GetIntValue(TW_IS_ENCRYPTED) == 0 || skip_decryption) && (TWFunc::Path_Exists(SCRIPT_FILE_TMP) || TWFunc::Path_Exists(orsFile))) {
		OpenRecoveryScript::Run_OpenRecoveryScript();
	}

	char encrypt_status[PROPERTY_VALUE_MAX];
	property_get("ro.crypto.state", encrypt_status, "");
	if (strcmp(encrypt_status, "") == 0 || strcmp(encrypt_status, "encrypted") == 0) {
		int st = TWFunc::check_encrypt_status();
		if (st != 0) {
			strcpy(encrypt_status, "encrypted");
			if (st == 1 || st == 3)
				strcpy(encrypt_status, "encrypted with FDE");
			else if (st == 2)
				strcpy(encrypt_status, "encrypted with FBE");
			if (st == 3)
				gui_msg(Msg(msg::kWarning,"pb_encrypt_cn=Multiple Encryption Details Cached"));
		}
		else
			strcpy(encrypt_status, "unencrypted");
	}
	else if (strncmp(encrypt_status, "encrypted", 9) == 0 && TWFunc::check_encrypt_status() == 0)
		strcpy(encrypt_status, "unencrypted");
	gui_msg(Msg(msg::kProcess,"pb_encrypt_st=Encryption Status : {1}")(encrypt_status));

	property_get("ro.product.brand", encrypt_status, "");
	DataManager::SetValue("pb_device_manufacturer", std::string(encrypt_status));
	property_get("ro.product.device", encrypt_status, "");
	DataManager::SetValue("pb_device", std::string(encrypt_status));
	property_get("ro.product.model", encrypt_status, "");
	DataManager::SetValue("pb_device_name", std::string(encrypt_status));
	DataManager::SetValue("pb_build", string(BUILD));

#ifdef TW_HAS_MTP
	char mtp_crash_check[PROPERTY_VALUE_MAX];
	property_get("mtp.crash_check", mtp_crash_check, "0");
	if (DataManager::GetIntValue("tw_mtp_enabled")
			&& !strcmp(mtp_crash_check, "0") && !crash_counter
			&& (!DataManager::GetIntValue(TW_IS_ENCRYPTED) || DataManager::GetIntValue(TW_IS_DECRYPTED))) {
		property_set("mtp.crash_check", "1");
		LOGINFO("Starting MTP\n");
		if (!PartitionManager.Enable_MTP())
			PartitionManager.Disable_MTP();
		else
			gui_msg("mtp_enabled=MTP Enabled");
		property_set("mtp.crash_check", "0");
	} else if (strcmp(mtp_crash_check, "0")) {
		gui_warn("mtp_crash=MTP Crashed, not starting MTP on boot.");
		DataManager::SetValue("tw_mtp_enabled", 0);
		PartitionManager.Disable_MTP();
	} else if (crash_counter == 1) {
		LOGINFO("TWRP crashed; disabling MTP as a precaution.\n");
		PartitionManager.Disable_MTP();
	}
#endif

#ifndef TW_OEM_BUILD
	// Check if system has never been changed
	TWPartition* sys = PartitionManager.Find_Partition_By_Path(PartitionManager.Get_Android_Root_Path());
	TWPartition* ven = PartitionManager.Find_Partition_By_Path("/vendor");
	if (sys) {
		if (sys->Get_Super_Status()) {
#ifdef TW_INCLUDE_CRYPTO
			std::string recoveryLogDir(DATA_LOGS_DIR);
			recoveryLogDir += "/recovery";
			if (!TWFunc::Path_Exists(recoveryLogDir)) {
				bool created = PartitionManager.Recreate_Logs_Dir();
				if (!created)
					LOGERR("Unable to create log directory for TWRP\n");
			}
			DataManager::ReadSettingsFile();
#endif
		} else {
			if ((DataManager::GetIntValue("tw_mount_system_ro") == 0 && sys->Check_Lifetime_Writes() == 0) || DataManager::GetIntValue("tw_mount_system_ro") == 2) {
				if (DataManager::GetIntValue("tw_never_show_system_ro_page") == 0) {
					DataManager::SetValue("tw_back", "main");
					if (gui_startPage("system_readonly", 1, 1) != 0) {
						LOGERR("Failed to start system_readonly GUI page.\n");
					}
				} else if (DataManager::GetIntValue("tw_mount_system_ro") == 0) {
					sys->Change_Mount_Read_Only(false);
					if (ven)
						ven->Change_Mount_Read_Only(false);
				}
			} else if (DataManager::GetIntValue("tw_mount_system_ro") == 1) {
				// Do nothing, user selected to leave system read only
			} else {
				sys->Change_Mount_Read_Only(false);
				if (ven)
					ven->Change_Mount_Read_Only(false);
			}
		}
	}
#endif

	TWFunc::Update_Log_File();

	adb_bu_fifo->threadAdbBuFifo();

	if (PartitionManager.Get_Android_Root_Path() == "/system_root" && !DataManager::GetIntValue(PB_MOUNT_SYSTEM_AS_ROOT))
	{
		PartitionManager.Change_System_Root(false);
	}

#ifndef TW_OEM_BUILD
	// Disable flashing of stock recovery
	TWFunc::Disable_Stock_Recovery_Replace();
#endif
	if (property_get_bool("twrp.decrypt.done", false))
		PartitionManager.Mount_All_Storage();
}

static void reboot() {
	gui_msg(Msg("rebooting=Rebooting..."));
	TWFunc::Update_Log_File();
	string Reboot_Arg;

	DataManager::GetValue("tw_reboot_arg", Reboot_Arg);
	if (Reboot_Arg == "recovery")
		TWFunc::tw_reboot(rb_recovery);
	else if (Reboot_Arg == "poweroff")
		TWFunc::tw_reboot(rb_poweroff);
	else if (Reboot_Arg == "bootloader")
		TWFunc::tw_reboot(rb_bootloader);
	else if (Reboot_Arg == "download")
		TWFunc::tw_reboot(rb_download);
	else if (Reboot_Arg == "edl")
		TWFunc::tw_reboot(rb_edl);
	else if (Reboot_Arg == "fastboot")
		TWFunc::tw_reboot(rb_fastboot);
	else
		TWFunc::tw_reboot(rb_system);
}

int main(int argc, char **argv) {
	// Recovery needs to install world-readable files, so clear umask
	// set by init
	umask(0);
	Log_Offset = 0;

	// Set up temporary log file (/tmp/recovery.log)
	freopen(TMP_LOG_FILE, "a", stdout);
	setbuf(stdout, NULL);
	freopen(TMP_LOG_FILE, "a", stderr);
	setbuf(stderr, NULL);

	signal(SIGPIPE, SIG_IGN);

	// Handle ADB sideload
	if (argc == 3 && strcmp(argv[1], "--adbd") == 0) {
		property_set("ctl.stop", "adbd");
#ifdef TW_USE_NEW_MINADBD
		//adb_server_main(0, DEFAULT_ADB_PORT, -1); TODO fix this for android8
		// minadbd_main();
#else
		adb_main(argv[2]);
#endif
		return 0;
	}

#ifdef RECOVERY_SDCARD_ON_DATA
	datamedia = true;
#endif

	property_set("ro.twrp.boot", "1");
	property_set("ro.twrp.version", TW_MAIN_VERSION_STR);
	property_set("ro.pb.version", PB_BUILD);

	time_t StartupTime = time(NULL);
	printf("Starting PitchBlackRecovery %s (pid %s)\n", PB_BUILD, ctime(&StartupTime));
	std::string ver = std::string(PB_BUILD);
	DataManager::SetValue("pb_ver", ver.substr(0, ver.find("-")) );
	DataManager::SetValue("pb_info", ver.substr(ver.find("-") + 1));
#ifdef MTAINER
	DataManager::SetValue("pb_maintainer", std::string(MTAINER));
#endif
	// Load default values to set DataManager constants and handle ifdefs
	DataManager::SetDefaultValues();
	printf("Starting the UI...\n");
	gui_init();

	// Load up all the resources
	gui_loadResources();

	gui_print("********************************* \n");
	gui_print("PitchBlack Recovery: Welcome! ^_^ \n");
	gui_print("Maintained By PBRP Team \n");
	gui_print("********************************* \n");
	string null;
	TWFunc::Exec_Cmd("getprop ro.omni.version > /tmp/prop.info && mv /tmp/prop.info /sdcard/PBRP/pbrp.info", null);
	if(!null.empty())
		LOGERR("Failed To Copy prop.info\n");

	startupArgs startup;
	startup.parse(&argc, &argv);
	twrpAdbBuFifo *adb_bu_fifo = new twrpAdbBuFifo();
	TWFunc::Clear_Bootloader_Message();

	if (startup.Get_Fastboot_Mode()) {
		LOGINFO("starting fastboot\n");
		gui_msg(Msg("fastboot_console_msg=Entered Fastboot mode..."));
		if (gui_startPage("fastboot", 1, 1) != 0) {
			LOGERR("Failed to start fastbootd page.\n");
		}
		delete adb_bu_fifo;
		TWFunc::Update_Intent_File(startup.Get_Intent());

		reboot();
		return 0;
	} else {
		process_recovery_mode(adb_bu_fifo, startup.Should_Skip_Decryption());
	}

	PageManager::LoadLanguage(DataManager::GetStrValue("tw_language"));
	GUIConsole::Translate_Now();

	// Launch the main GUI
	gui_start();
	delete adb_bu_fifo;
	TWFunc::Update_Intent_File(startup.Get_Intent());

	reboot();

	return 0;
}
