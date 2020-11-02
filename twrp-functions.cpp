/*
	Copyright 2012-2020 TeamWin
	This file is part of TWRP/TeamWin Recovery Project.

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
#include <unistd.h>
#include <vector>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cctype>
#include <algorithm>
#include <selinux/label.h>
#include "twrp-functions.hpp"
#include "twcommon.h"
#include "gui/gui.hpp"
#ifndef BUILD_TWRPTAR_MAIN
#include "data.hpp"
#include "partitions.hpp"
#include "variables.h"
#include "bootloader_message/include/bootloader_message/bootloader_message.h"
#include "cutils/properties.h"
#include "cutils/android_reboot.h"
#include <sys/reboot.h>
#endif // ndef BUILD_TWRPTAR_MAIN
#ifndef TW_EXCLUDE_ENCRYPTED_BACKUPS
	#include "openaes/inc/oaes_lib.h"
#endif
#include "set_metadata.h"

extern "C" {
	#include "libcrecovery/common.h"
}
#ifdef TW_INCLUDE_LIBRESETPROP
    #include <resetprop.h>
#endif

static const string tmp = "/tmp/pb/";
static const string ramdisk = tmp + "ramdisk/";
static const string split_img = tmp + "split_img/";
static string default_prop = ramdisk + "default.prop";
static string fstab1 = PartitionManager.Get_Android_Root_Path() + "/vendor/etc";
static string fstab2 = "/vendor/etc";
static int trb_en = 0;
static string dtb = "", ram = "";

struct selabel_handle *selinux_handle;

/* Execute a command */
int TWFunc::Exec_Cmd(const string& cmd, string &result, bool combine_stderr) {
	FILE* exec;
	char buffer[130];
	int ret = 0;
	std::string popen_cmd = cmd;
	if (combine_stderr)
		popen_cmd = cmd + " 2>&1";
	exec = __popen(popen_cmd.c_str(), "r");

	while (!feof(exec)) {
		if (fgets(buffer, 128, exec) != NULL) {
			result += buffer;
		}
	}
	ret = __pclose(exec);
	return ret;
}

int TWFunc::Exec_Cmd(const string& cmd, bool Show_Errors, bool retn) {
	pid_t pid;
	int status;
	switch(pid = fork())
	{
		case -1:
			LOGERR("Exec_Cmd(): vfork failed: %d!\n", errno);
			return -1;
		case 0: // child
			execl("/sbin/sh", "sh", "-c", cmd.c_str(), NULL);
			_exit(127);
			break;
		default:
		{
			int ret = TWFunc::Wait_For_Child(pid, &status, cmd, Show_Errors, retn);

			if (retn)
				return ret;

			if (ret != 0)
				return -1;
			else
				return 0;
		}
	}
}

// Returns "file.name" from a full /path/to/file.name
string TWFunc::Get_Filename(const string& Path) {
	size_t pos = Path.find_last_of("/");
	if (pos != string::npos) {
		string Filename;
		Filename = Path.substr(pos + 1, Path.size() - pos - 1);
		return Filename;
	} else
		return Path;
}

// Returns "/path/to/" from a full /path/to/file.name
string TWFunc::Get_Path(const string& Path) {
	size_t pos = Path.find_last_of("/");
	if (pos != string::npos) {
		string Pathonly;
		Pathonly = Path.substr(0, pos + 1);
		return Pathonly;
	} else
		return Path;
}

string TWFunc::Get_output(const string& cmd) {
	string data;
	FILE * stream;
	const int max_buffer = 256;
	char buffer[max_buffer];
	string s = cmd + " 2>&1";

	stream = popen(s.c_str(), "r");
	if (stream) {
		while (!feof(stream))
		if (fgets(buffer, max_buffer, stream) != NULL) data.append(buffer);
			pclose(stream);
	}
	return data;
}

int TWFunc::Wait_For_Child(pid_t pid, int *status, string Child_Name, bool Show_Errors, bool retn) {
	pid_t rc_pid;

	rc_pid = waitpid(pid, status, 0);
	if (rc_pid > 0) {
		if (WIFSIGNALED(*status)) {
			if (Show_Errors)
				gui_msg(Msg(msg::kError, "pid_signal={1} process ended with signal: {2}")(Child_Name)(WTERMSIG(*status))); // Seg fault or some other non-graceful termination
			return -1;
		} else if (WEXITSTATUS(*status) == 0) {
			LOGINFO("%s process ended with RC=%d\n", Child_Name.c_str(), WEXITSTATUS(*status)); // Success
		} else {
			if (Show_Errors)
				gui_msg(Msg(msg::kError, "pid_error={1} process ended with ERROR: {2}")(Child_Name)(WEXITSTATUS(*status))); // Graceful exit, but there was an error

			if (retn)
				return WEXITSTATUS(*status);
			return -1;
		}
	} else { // no PID returned
		if (errno == ECHILD)
			LOGERR("%s no child process exist\n", Child_Name.c_str());
		else {
			LOGERR("%s Unexpected error %d\n", Child_Name.c_str(), errno);
			return -1;
		}
	}
	return 0;
}

int TWFunc::Wait_For_Child_Timeout(pid_t pid, int *status, const string& Child_Name, int timeout) {
	pid_t retpid = waitpid(pid, status, WNOHANG);
	for (; retpid == 0 && timeout; --timeout) {
		sleep(1);
		retpid = waitpid(pid, status, WNOHANG);
	}
	if (retpid == 0 && timeout == 0) {
		LOGERR("%s took too long, killing process\n", Child_Name.c_str());
		kill(pid, SIGKILL);
		for (timeout = 5; retpid == 0 && timeout; --timeout) {
			sleep(1);
			retpid = waitpid(pid, status, WNOHANG);
		}
		if (retpid)
			LOGINFO("Child process killed successfully\n");
		else
			LOGINFO("Child process took too long to kill, may be a zombie process\n");
		return -1;
	} else if (retpid > 0) {
		if (WIFSIGNALED(*status)) {
			gui_msg(Msg(msg::kError, "pid_signal={1} process ended with signal: {2}")(Child_Name)(WTERMSIG(*status))); // Seg fault or some other non-graceful termination
			return -1;
		}
	} else if (retpid < 0) { // no PID returned
		if (errno == ECHILD)
			LOGERR("%s no child process exist\n", Child_Name.c_str());
		else {
			LOGERR("%s Unexpected error %d\n", Child_Name.c_str(), errno);
			return -1;
		}
	}
	return 0;
}

bool TWFunc::Path_Exists(string Path) {
	struct stat st;
	return stat(Path.c_str(), &st) == 0;
}

Archive_Type TWFunc::Get_File_Type(string fn) {
	string::size_type i = 0;
	int firstbyte = 0, secondbyte = 0;
	char header[3];

	ifstream f;
	f.open(fn.c_str(), ios::in | ios::binary);
	f.get(header, 3);
	f.close();
	firstbyte = header[i] & 0xff;
	secondbyte = header[++i] & 0xff;

	if (firstbyte == 0x1f && secondbyte == 0x8b)
		return COMPRESSED;
	else if (firstbyte == 0x4f && secondbyte == 0x41)
		return ENCRYPTED;
	return UNCOMPRESSED; // default
}

int TWFunc::Try_Decrypting_File(string fn, string password) {
#ifndef TW_EXCLUDE_ENCRYPTED_BACKUPS
	OAES_CTX * ctx = NULL;
	uint8_t _key_data[32] = "";
	FILE *f;
	uint8_t buffer[4096];
	uint8_t *buffer_out = NULL;
	uint8_t *ptr = NULL;
	size_t read_len = 0, out_len = 0;
	int firstbyte = 0, secondbyte = 0;
	size_t _j = 0;
	size_t _key_data_len = 0;

	// mostly kanged from OpenAES oaes.c
	for ( _j = 0; _j < 32; _j++ )
		_key_data[_j] = _j + 1;
	_key_data_len = password.size();
	if ( 16 >= _key_data_len )
		_key_data_len = 16;
	else if ( 24 >= _key_data_len )
		_key_data_len = 24;
	else
		_key_data_len = 32;
	memcpy(_key_data, password.c_str(), password.size());

	ctx = oaes_alloc();
	if (ctx == NULL) {
		LOGERR("Failed to allocate OAES\n");
		return -1;
	}

	oaes_key_import_data(ctx, _key_data, _key_data_len);

	f = fopen(fn.c_str(), "rb");
	if (f == NULL) {
		LOGERR("Failed to open '%s' to try decrypt: %s\n", fn.c_str(), strerror(errno));
		oaes_free(&ctx);
		return -1;
	}
	read_len = fread(buffer, sizeof(uint8_t), 4096, f);
	if (read_len <= 0) {
		LOGERR("Read size during try decrypt failed: %s\n", strerror(errno));
		fclose(f);
		oaes_free(&ctx);
		return -1;
	}
	if (oaes_decrypt(ctx, buffer, read_len, NULL, &out_len) != OAES_RET_SUCCESS) {
		LOGERR("Error: Failed to retrieve required buffer size for trying decryption.\n");
		fclose(f);
		oaes_free(&ctx);
		return -1;
	}
	buffer_out = (uint8_t *) calloc(out_len, sizeof(char));
	if (buffer_out == NULL) {
		LOGERR("Failed to allocate output buffer for try decrypt.\n");
		fclose(f);
		oaes_free(&ctx);
		return -1;
	}
	if (oaes_decrypt(ctx, buffer, read_len, buffer_out, &out_len) != OAES_RET_SUCCESS) {
		LOGERR("Failed to decrypt file '%s'\n", fn.c_str());
		fclose(f);
		free(buffer_out);
		oaes_free(&ctx);
		return 0;
	}
	fclose(f);
	oaes_free(&ctx);
	if (out_len < 2) {
		LOGINFO("Successfully decrypted '%s' but read length too small.\n", fn.c_str());
		free(buffer_out);
		return 1; // Decrypted successfully
	}
	ptr = buffer_out;
	firstbyte = *ptr & 0xff;
	ptr++;
	secondbyte = *ptr & 0xff;
	if (firstbyte == 0x1f && secondbyte == 0x8b) {
		LOGINFO("Successfully decrypted '%s' and file is compressed.\n", fn.c_str());
		free(buffer_out);
		return 3; // Compressed
	}
	if (out_len >= 262) {
		ptr = buffer_out + 257;
		if (strncmp((char*)ptr, "ustar", 5) == 0) {
			LOGINFO("Successfully decrypted '%s' and file is tar format.\n", fn.c_str());
			free(buffer_out);
			return 2; // Tar
		}
	}
	free(buffer_out);
	LOGINFO("No errors decrypting '%s' but no known file format.\n", fn.c_str());
	return 1; // Decrypted successfully
#else
	LOGERR("Encrypted backup support not included.\n");
	return -1;
#endif
}

unsigned long TWFunc::Get_File_Size(const string& Path) {
	struct stat st;

	if (stat(Path.c_str(), &st) != 0)
		return 0;
	return st.st_size;
}

std::string TWFunc::Remove_Beginning_Slash(const std::string& path) {
	std::string res;
	size_t pos = path.find_first_of("/");
	if (pos != std::string::npos) {
		res = path.substr(pos+1);
	}
	return res;
}

std::string TWFunc::Remove_Trailing_Slashes(const std::string& path, bool leaveLast)
{
	std::string res;
	size_t last_idx = 0, idx = 0;

	while (last_idx != std::string::npos)
	{
		if (last_idx != 0)
			res += '/';

		idx = path.find_first_of('/', last_idx);
		if (idx == std::string::npos) {
			res += path.substr(last_idx, idx);
			break;
		}

		res += path.substr(last_idx, idx-last_idx);
		last_idx = path.find_first_not_of('/', idx);
	}

	if (leaveLast)
		res += '/';
	return res;
}

void TWFunc::Strip_Quotes(char* &str) {
	if (strlen(str) > 0 && str[0] == '\"')
		str++;
	if (strlen(str) > 0 && str[strlen(str)-1] == '\"')
		str[strlen(str)-1] = 0;
}

vector<string> TWFunc::split_string(const string &in, char del, bool skip_empty) {
	vector<string> res;

	if (in.empty() || del == '\0')
		return res;

	string field;
	istringstream f(in);
	if (del == '\n') {
		while (getline(f, field)) {
			if (field.empty() && skip_empty)
				continue;
			res.push_back(field);
		}
	} else {
		while (getline(f, field, del)) {
			if (field.empty() && skip_empty)
				continue;
			res.push_back(field);
		}
	}
	return res;
}

timespec TWFunc::timespec_diff(timespec& start, timespec& end)
{
	timespec temp;
	if ((end.tv_nsec-start.tv_nsec)<0) {
		temp.tv_sec = end.tv_sec-start.tv_sec-1;
		temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}
	return temp;
}

int32_t TWFunc::timespec_diff_ms(timespec& start, timespec& end)
{
	return ((end.tv_sec * 1000) + end.tv_nsec/1000000) -
			((start.tv_sec * 1000) + start.tv_nsec/1000000);
}

#ifndef BUILD_TWRPTAR_MAIN

// Returns "/path" from a full /path/to/file.name
string TWFunc::Get_Root_Path(const string& Path) {
	string Local_Path = Path;

	// Make sure that we have a leading slash
	if (Local_Path.substr(0, 1) != "/")
		Local_Path = "/" + Local_Path;

	// Trim the path to get the root path only
	size_t position = Local_Path.find("/", 2);
	if (position != string::npos) {
		Local_Path.resize(position);
	}
	return Local_Path;
}

void TWFunc::install_htc_dumlock(void) {
	int need_libs = 0;

	if (!PartitionManager.Mount_By_Path(PartitionManager.Get_Android_Root_Path(), true))
		return;

	if (!PartitionManager.Mount_By_Path("/data", true))
		return;

	gui_msg("install_dumlock=Installing HTC Dumlock to system...");
	copy_file(TWHTCD_PATH "htcdumlocksys", "/system/bin/htcdumlock", 0755);
	if (!Path_Exists("/system/bin/flash_image")) {
		LOGINFO("Installing flash_image...\n");
		copy_file(TWHTCD_PATH "flash_imagesys", "/system/bin/flash_image", 0755);
		need_libs = 1;
	} else
		LOGINFO("flash_image is already installed, skipping...\n");
	if (!Path_Exists("/system/bin/dump_image")) {
		LOGINFO("Installing dump_image...\n");
		copy_file(TWHTCD_PATH "dump_imagesys", "/system/bin/dump_image", 0755);
		need_libs = 1;
	} else
		LOGINFO("dump_image is already installed, skipping...\n");
	if (need_libs) {
		LOGINFO("Installing libs needed for flash_image and dump_image...\n");
		copy_file(TWHTCD_PATH "libbmlutils.so", "/system/lib/libbmlutils.so", 0644);
		copy_file(TWHTCD_PATH "libflashutils.so", "/system/lib/libflashutils.so", 0644);
		copy_file(TWHTCD_PATH "libmmcutils.so", "/system/lib/libmmcutils.so", 0644);
		copy_file(TWHTCD_PATH "libmtdutils.so", "/system/lib/libmtdutils.so", 0644);
	}
	LOGINFO("Installing HTC Dumlock app...\n");
	mkdir("/data/app", 0777);
	unlink("/data/app/com.teamwin.htcdumlock*");
	copy_file(TWHTCD_PATH "HTCDumlock.apk", "/data/app/com.teamwin.htcdumlock.apk", 0777);
	sync();
	gui_msg("done=Done.");
}

void TWFunc::htc_dumlock_restore_original_boot(void) {
	if (!PartitionManager.Mount_By_Path("/sdcard", true))
		return;

	gui_msg("dumlock_restore=Restoring original boot...");
	Exec_Cmd("htcdumlock restore");
	gui_msg("done=Done.");
}

void TWFunc::htc_dumlock_reflash_recovery_to_boot(void) {
	if (!PartitionManager.Mount_By_Path("/sdcard", true))
		return;
	gui_msg("dumlock_reflash=Reflashing recovery to boot...");
	Exec_Cmd("htcdumlock recovery noreboot");
	gui_msg("done=Done.");
}

int TWFunc::Recursive_Mkdir(string Path) {
	std::vector<std::string> parts = Split_String(Path, "/", true);
	std::string cur_path;
	for (size_t i = 0; i < parts.size(); ++i) {
		cur_path += "/" + parts[i];
		if (!TWFunc::Path_Exists(cur_path)) {
			if (mkdir(cur_path.c_str(), 0777)) {
				gui_msg(Msg(msg::kError, "create_folder_strerr=Can not create '{1}' folder ({2}).")(cur_path)(strerror(errno)));
				return false;
			} else {
				tw_set_default_metadata(cur_path.c_str());
			}
		}
	}
	return true;
}

void TWFunc::GUI_Operation_Text(string Read_Value, string Default_Text) {
	string Display_Text;

	DataManager::GetValue(Read_Value, Display_Text);
	if (Display_Text.empty())
		Display_Text = Default_Text;

	DataManager::SetValue("tw_operation", Display_Text);
	DataManager::SetValue("tw_partition", "");
}

void TWFunc::GUI_Operation_Text(string Read_Value, string Partition_Name, string Default_Text) {
	string Display_Text;

	DataManager::GetValue(Read_Value, Display_Text);
	if (Display_Text.empty())
		Display_Text = Default_Text;

	DataManager::SetValue("tw_operation", Display_Text);
	DataManager::SetValue("tw_partition", Partition_Name);
}

void TWFunc::Copy_Log(string Source, string Destination) {
	int logPipe[2];
	int pigz_pid;
	int destination_fd;
	std::string destLogBuffer;

	PartitionManager.Mount_By_Path(Destination, false);

	size_t extPos = Destination.find(".gz");
	std::string uncompressedLog(Destination);
	uncompressedLog.replace(extPos, Destination.length(), "");

	if (Path_Exists(Destination)) {
		Archive_Type type = Get_File_Type(Destination);
		if (type == COMPRESSED) {
			std::string destFileBuffer;
			std::string getCompressedContents = "pigz -c -d " + Destination;
			if (Exec_Cmd(getCompressedContents, destFileBuffer) < 0) {
				LOGINFO("Unable to get destination logfile contents.\n");
				return;
			}
			destLogBuffer.append(destFileBuffer);
		}
	} else if (Path_Exists(uncompressedLog)) {
		std::ifstream uncompressedIfs(uncompressedLog.c_str());
		std::stringstream uncompressedSS;
		uncompressedSS << uncompressedIfs.rdbuf();
		uncompressedIfs.close();
		std::string uncompressedLogBuffer(uncompressedSS.str());
		destLogBuffer.append(uncompressedLogBuffer);
		std::remove(uncompressedLog.c_str());
	}

	std::ifstream ifs(Source.c_str());
	std::stringstream ss;
	ss << ifs.rdbuf();
	std::string srcLogBuffer(ss.str());
	ifs.close();

	if (pipe(logPipe) < 0) {
		LOGINFO("Unable to open pipe to write to persistent log file: %s\n", Destination.c_str());
	}

	destination_fd = open(Destination.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);

	pigz_pid = fork();
	if (pigz_pid < 0) {
		LOGINFO("fork() failed\n");
		close(destination_fd);
		close(logPipe[0]);
		close(logPipe[1]);
	} else if (pigz_pid == 0) {
		close(logPipe[1]);
		dup2(logPipe[0], fileno(stdin));
		dup2(destination_fd, fileno(stdout));
		if (execlp("pigz", "pigz", "-", NULL) < 0) {
			close(destination_fd);
			close(logPipe[0]);
			_exit(-1);
		}
	} else {
		close(logPipe[0]);
		if (write(logPipe[1], destLogBuffer.c_str(), destLogBuffer.size()) < 0) {
			LOGINFO("Unable to append to persistent log: %s\n", Destination.c_str());
			close(logPipe[1]);
			close(destination_fd);
			return;
		}
		if (write(logPipe[1], srcLogBuffer.c_str(), srcLogBuffer.size()) < 0) {
			LOGINFO("Unable to append to persistent log: %s\n", Destination.c_str());
			close(logPipe[1]);
			close(destination_fd);
			return;
		}
		close(logPipe[1]);
	}
	close(destination_fd);
}

void TWFunc::Update_Log_File(void) {
	std::string recoveryDir = get_log_dir() + "recovery/";

	if (get_log_dir() == CACHE_LOGS_DIR) {
		if (!PartitionManager.Mount_By_Path(CACHE_LOGS_DIR, false)) {
			LOGINFO("Failed to mount %s for TWFunc::Update_Log_File\n", CACHE_LOGS_DIR);
		}
	}

	if (!TWFunc::Path_Exists(recoveryDir)) {
		LOGINFO("Recreating %s folder.\n", recoveryDir.c_str());
		if (!Create_Dir_Recursive(recoveryDir,  S_IRWXU | S_IRWXG | S_IWGRP | S_IXGRP, 0, 0)) {
			LOGINFO("Unable to create %s folder.\n", recoveryDir.c_str());
		}
	}

	std::string logCopy = recoveryDir + "log.gz";
	std::string lastLogCopy = recoveryDir + "last_log.gz";
	copy_file(logCopy, lastLogCopy, 600);
	Copy_Log(TMP_LOG_FILE, logCopy);
	chown(logCopy.c_str(), 1000, 1000);
	chmod(logCopy.c_str(), 0600);
	chmod(lastLogCopy.c_str(), 0640);

	if (get_log_dir() == CACHE_LOGS_DIR) {
		if (PartitionManager.Mount_By_Path("/cache", false)) {
			if (unlink("/cache/recovery/command") && errno != ENOENT) {
				LOGINFO("Can't unlink %s\n", "/cache/recovery/command");
			}
		}
	}
	sync();
}

void TWFunc::Clear_Bootloader_Message() {
	std::string err;
	if (!clear_bootloader_message(&err)) {
		LOGINFO("%s\n", err.c_str());
	}
}

void TWFunc::Update_Intent_File(string Intent) {
	if (PartitionManager.Mount_By_Path("/cache", false) && !Intent.empty()) {
		TWFunc::write_to_file("/cache/recovery/intent", Intent);
	}
}

// reboot: Reboot the system. Return -1 on error, no return on success
int TWFunc::tw_reboot(RebootCommand command)
{
	DataManager::Flush();
	Update_Log_File();

	// Always force a sync before we reboot
	sync();

	switch (command) {
		case rb_current:
		case rb_system:
			Update_Intent_File("s");
			sync();
			check_and_run_script("/sbin/rebootsystem.sh", "reboot system");
#ifdef ANDROID_RB_PROPERTY
			return property_set(ANDROID_RB_PROPERTY, "reboot,");
#elif defined(ANDROID_RB_RESTART)
			return android_reboot(ANDROID_RB_RESTART, 0, 0);
#else
			return reboot(RB_AUTOBOOT);
#endif
		case rb_recovery:
			check_and_run_script("/sbin/rebootrecovery.sh", "reboot recovery");
			return property_set(ANDROID_RB_PROPERTY, "reboot,recovery");
		case rb_bootloader:
			check_and_run_script("/sbin/rebootbootloader.sh", "reboot bootloader");
			return property_set(ANDROID_RB_PROPERTY, "reboot,bootloader");
		case rb_poweroff:
			check_and_run_script("/sbin/poweroff.sh", "power off");
#ifdef ANDROID_RB_PROPERTY
			return property_set(ANDROID_RB_PROPERTY, "shutdown,");
#elif defined(ANDROID_RB_POWEROFF)
			return android_reboot(ANDROID_RB_POWEROFF, 0, 0);
#else
			return reboot(RB_POWER_OFF);
#endif
		case rb_download:
			check_and_run_script("/sbin/rebootdownload.sh", "reboot download");
			return property_set(ANDROID_RB_PROPERTY, "reboot,download");
		case rb_edl:
			check_and_run_script("/sbin/rebootedl.sh", "reboot edl");
			return property_set(ANDROID_RB_PROPERTY, "reboot,edl");
		case rb_fastboot:
			return property_set(ANDROID_RB_PROPERTY, "reboot,fastboot");
		default:
			return -1;
	}
	return -1;
}

void TWFunc::check_and_run_script(const char* script_file, const char* display_name)
{
	// Check for and run startup script if script exists
	struct stat st;
	if (stat(script_file, &st) == 0) {
		gui_msg(Msg("run_script=Running {1} script...")(display_name));
		chmod(script_file, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
		TWFunc::Exec_Cmd(script_file);
		gui_msg("done=Done.");
	}
}

int TWFunc::removeDir(const string path, bool skipParent) {
	DIR *d = opendir(path.c_str());
	int r = 0;
	string new_path;

	if (d == NULL) {
		gui_msg(Msg(msg::kError, "error_opening_strerr=Error opening: '{1}' ({2})")(path)(strerror(errno)));
		return -1;
	}

	if (d) {
		struct dirent *p;
		while (!r && (p = readdir(d))) {
			if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
				continue;
			new_path = path + "/";
			new_path.append(p->d_name);
			if (p->d_type == DT_DIR) {
				r = removeDir(new_path, true);
				if (!r) {
					if (p->d_type == DT_DIR)
						r = rmdir(new_path.c_str());
					else
						LOGINFO("Unable to removeDir '%s': %s\n", new_path.c_str(), strerror(errno));
				}
			} else if (p->d_type == DT_REG || p->d_type == DT_LNK || p->d_type == DT_FIFO || p->d_type == DT_SOCK) {
				r = unlink(new_path.c_str());
				if (r != 0) {
					LOGINFO("Unable to unlink '%s: %s'\n", new_path.c_str(), strerror(errno));
				}
			}
		}
		closedir(d);

		if (!r) {
			if (skipParent)
				return 0;
			else
				r = rmdir(path.c_str());
		}
	}
	return r;
}

int TWFunc::copy_file(string src, string dst, int mode) {
	PartitionManager.Mount_By_Path(src, false);
	PartitionManager.Mount_By_Path(dst, false);
	if (!Path_Exists(src)) {
		LOGINFO("Path %s does not exist. Unable to copy %s\n", src.c_str(), dst.c_str());
		return -1;
	}
	std::ifstream srcfile(src.c_str(), ios::binary);
	std::ofstream dstfile(dst.c_str(), ios::binary);
	dstfile << srcfile.rdbuf();
	if (!dstfile.bad()) {
		LOGINFO("Copied file %s to %s\n", src.c_str(), dst.c_str());
	}
	else {
		LOGINFO("Unable to copy file %s to %s\n", src.c_str(), dst.c_str());
		return -1;
	}

	srcfile.close();
	dstfile.close();
	if (chmod(dst.c_str(), mode) != 0)
		return -1;
	return 0;
}

unsigned int TWFunc::Get_D_Type_From_Stat(string Path) {
	struct stat st;

	stat(Path.c_str(), &st);
	if (st.st_mode & S_IFDIR)
		return DT_DIR;
	else if (st.st_mode & S_IFBLK)
		return DT_BLK;
	else if (st.st_mode & S_IFCHR)
		return DT_CHR;
	else if (st.st_mode & S_IFIFO)
		return DT_FIFO;
	else if (st.st_mode & S_IFLNK)
		return DT_LNK;
	else if (st.st_mode & S_IFREG)
		return DT_REG;
	else if (st.st_mode & S_IFSOCK)
		return DT_SOCK;
	return DT_UNKNOWN;
}

int TWFunc::read_file(string fn, string& results) {
	ifstream file;
	file.open(fn.c_str(), ios::in);

	if (file.is_open()) {
		file >> results;
		file.close();
		return 0;
	}

	LOGINFO("Cannot find file %s\n", fn.c_str());
	return -1;
}

int TWFunc::read_file(string fn, vector<string>& results) {
	ifstream file;
	string line;
	file.open(fn.c_str(), ios::in);
	if (file.is_open()) {
		while (getline(file, line))
			results.push_back(line);
		file.close();
		return 0;
	}
	LOGINFO("Cannot find file %s\n", fn.c_str());
	return -1;
}

int TWFunc::read_file(string fn, uint64_t& results) {
	ifstream file;
	file.open(fn.c_str(), ios::in);

	if (file.is_open()) {
		file >> results;
		file.close();
		return 0;
	}

	LOGINFO("Cannot find file %s\n", fn.c_str());
	return -1;
}

int TWFunc::write_to_file(const string& fn, const string& line) {
	FILE *file;
	file = fopen(fn.c_str(), "w");
	if (file != NULL) {
		fwrite(line.c_str(), line.size(), 1, file);
		fclose(file);
		return 0;
	}
	LOGINFO("Cannot find file %s\n", fn.c_str());
	return -1;
}

bool TWFunc::Try_Decrypting_Backup(string Restore_Path, string Password) {
	DIR* d;

	string Filename;
	Restore_Path += "/";
	d = opendir(Restore_Path.c_str());
	if (d == NULL) {
		gui_msg(Msg(msg::kError, "error_opening_strerr=Error opening: '{1}' ({2})")(Restore_Path)(strerror(errno)));
		return false;
	}

	struct dirent* de;
	while ((de = readdir(d)) != NULL) {
		Filename = Restore_Path;
		Filename += de->d_name;
		if (TWFunc::Get_File_Type(Filename) == ENCRYPTED) {
			if (TWFunc::Try_Decrypting_File(Filename, Password) < 2) {
				DataManager::SetValue("tw_restore_password", ""); // Clear the bad password
				DataManager::SetValue("tw_restore_display", "");  // Also clear the display mask
				closedir(d);
				return false;
			}
		}
	}
	closedir(d);
	return true;
}

string TWFunc::Get_Current_Date() {
	string Current_Date;
	time_t seconds = time(0);
	struct tm *t = localtime(&seconds);
	char timestamp[255];
	sprintf(timestamp,"%04d-%02d-%02d--%02d-%02d-%02d",t->tm_year+1900,t->tm_mon+1,t->tm_mday,t->tm_hour,t->tm_min,t->tm_sec);
	Current_Date = timestamp;
	return Current_Date;
}

string TWFunc::System_Property_Get(string Prop_Name) {
	return System_Property_Get(Prop_Name, PartitionManager, PartitionManager.Get_Android_Root_Path());
}

string TWFunc::System_Property_Get(string Prop_Name, TWPartitionManager &PartitionManager, string Mount_Point) {
	bool mount_state = PartitionManager.Is_Mounted_By_Path(Mount_Point);
	std::vector<string> buildprop;
	string propvalue;
	if (!PartitionManager.Mount_By_Path(Mount_Point, true))
		return propvalue;
	string prop_file = Mount_Point + "/build.prop";
	if (!TWFunc::Path_Exists(prop_file))
		prop_file = Mount_Point + "/system/build.prop"; // for devices with system as a root file system (e.g. Pixel)
	if (TWFunc::read_file(prop_file, buildprop) != 0) {
		LOGINFO("Unable to open build.prop for getting '%s'.\n", Prop_Name.c_str());
		DataManager::SetValue(TW_BACKUP_NAME, Get_Current_Date());
		if (!mount_state)
			PartitionManager.UnMount_By_Path(Mount_Point, false);
		return propvalue;
	}
	int line_count = buildprop.size();
	int index;
	size_t start_pos = 0, end_pos;
	string propname;
	for (index = 0; index < line_count; index++) {
		end_pos = buildprop.at(index).find("=", start_pos);
		propname = buildprop.at(index).substr(start_pos, end_pos);
		if (propname == Prop_Name) {
			propvalue = buildprop.at(index).substr(end_pos + 1, buildprop.at(index).size());
			if (!mount_state)
				PartitionManager.UnMount_By_Path(Mount_Point, false);
			return propvalue;
		}
	}
	if (!mount_state)
		PartitionManager.UnMount_By_Path(Mount_Point, false);
	return propvalue;
}

string TWFunc::File_Property_Get(string File_Path, string Prop_Name) {
 std::vector<string> buildprop;
 string propvalue;
 string prop_file = File_Path;
 if (TWFunc::read_file(prop_file, buildprop) != 0) {
		return propvalue;
	}
  int line_count = buildprop.size();
 int index;
 size_t start_pos = 0, end_pos;
 string propname;
 for (index = 0; index < line_count; index++) {
  end_pos = buildprop.at(index).find("=", start_pos);
  propname = buildprop.at(index).substr(start_pos, end_pos);
  if (propname == Prop_Name) {
   propvalue = buildprop.at(index).substr(end_pos + 1, buildprop.at(index).size());
    return propvalue;
  }
 }
 return propvalue;
}


void TWFunc::Auto_Generate_Backup_Name() {
	string propvalue = System_Property_Get("ro.build.display.id");
	if (propvalue.empty()) {
		DataManager::SetValue(TW_BACKUP_NAME, Get_Current_Date());
		return;
	}
	else {
		//remove periods from build display so it doesn't confuse the extension code
		propvalue.erase(remove(propvalue.begin(), propvalue.end(), '.'), propvalue.end());
	}
	string Backup_Name = Get_Current_Date();
	Backup_Name += "_" + propvalue;
	if (Backup_Name.size() > MAX_BACKUP_NAME_LEN)
		Backup_Name.resize(MAX_BACKUP_NAME_LEN);
	// Trailing spaces cause problems on some file systems, so remove them
	string space_check, space = " ";
	space_check = Backup_Name.substr(Backup_Name.size() - 1, 1);
	while (space_check == space) {
		Backup_Name.resize(Backup_Name.size() - 1);
		space_check = Backup_Name.substr(Backup_Name.size() - 1, 1);
	}
	replace(Backup_Name.begin(), Backup_Name.end(), ' ', '_');
	if (PartitionManager.Check_Backup_Name(Backup_Name, false, true) != 0) {
		LOGINFO("Auto generated backup name '%s' is not valid, using date instead.\n", Backup_Name.c_str());
		DataManager::SetValue(TW_BACKUP_NAME, Get_Current_Date());
	} else {
		DataManager::SetValue(TW_BACKUP_NAME, Backup_Name);
	}
}

void TWFunc::Fixup_Time_On_Boot(const string& time_paths /* = "" */)
{
#ifdef QCOM_RTC_FIX
	static bool fixed = false;
	if (fixed)
		return;

	LOGINFO("TWFunc::Fixup_Time: Pre-fix date and time: %s\n", TWFunc::Get_Current_Date().c_str());

	struct timeval tv;
	uint64_t offset = 0;
	std::string sepoch = "/sys/class/rtc/rtc0/since_epoch";

	if (TWFunc::read_file(sepoch, offset) == 0) {

		LOGINFO("TWFunc::Fixup_Time: Setting time offset from file %s\n", sepoch.c_str());

		tv.tv_sec = offset;
		tv.tv_usec = 0;
		settimeofday(&tv, NULL);

		gettimeofday(&tv, NULL);

		if (tv.tv_sec > 1517600000) { // Anything older then 2 Feb 2018 19:33:20 GMT will do nicely thank you ;)

			LOGINFO("TWFunc::Fixup_Time: Date and time corrected: %s\n", TWFunc::Get_Current_Date().c_str());
			fixed = true;
			return;

		}

	} else {

		LOGINFO("TWFunc::Fixup_Time: opening %s failed\n", sepoch.c_str());

	}

	LOGINFO("TWFunc::Fixup_Time: will attempt to use the ats files now.\n");

	// Devices with Qualcomm Snapdragon 800 do some shenanigans with RTC.
	// They never set it, it just ticks forward from 1970-01-01 00:00,
	// and then they have files /data/system/time/ats_* with 64bit offset
	// in miliseconds which, when added to the RTC, gives the correct time.
	// So, the time is: (offset_from_ats + value_from_RTC)
	// There are multiple ats files, they are for different systems? Bases?
	// Like, ats_1 is for modem and ats_2 is for TOD (time of day?).
	// Look at file time_genoff.h in CodeAurora, qcom-opensource/time-services

	std::vector<std::string> paths; // space separated list of paths
	if (time_paths.empty()) {
		paths = Split_String("/data/system/time/ /data/time/ /data/vendor/time/", " ");
		if (!PartitionManager.Mount_By_Path("/data", false))
			return;
	} else {
		// When specific path(s) are used, Fixup_Time needs those
		// partitions to already be mounted!
		paths = Split_String(time_paths, " ");
	}

	FILE *f;
	offset = 0;
	struct dirent *dt;
	std::string ats_path;

	// Prefer ats_2, it seems to be the one we want according to logcat on hammerhead
	// - it is the one for ATS_TOD (time of day?).
	// However, I never saw a device where the offset differs between ats files.
	for (size_t i = 0; i < paths.size(); ++i)
	{
		DIR *d = opendir(paths[i].c_str());
		if (!d)
			continue;

		while ((dt = readdir(d)))
		{
			if (dt->d_type != DT_REG || strncmp(dt->d_name, "ats_", 4) != 0)
				continue;

			if (ats_path.empty() || strcmp(dt->d_name, "ats_2") == 0)
				ats_path = paths[i] + dt->d_name;
		}

		closedir(d);
	}

	if (ats_path.empty()) {
		LOGINFO("TWFunc::Fixup_Time: no ats files found, leaving untouched!\n");
	} else if ((f = fopen(ats_path.c_str(), "r")) == NULL) {
		LOGINFO("TWFunc::Fixup_Time: failed to open file %s\n", ats_path.c_str());
	} else if (fread(&offset, sizeof(offset), 1, f) != 1) {
		LOGINFO("TWFunc::Fixup_Time: failed load uint64 from file %s\n", ats_path.c_str());
		fclose(f);
	} else {
		fclose(f);

		LOGINFO("TWFunc::Fixup_Time: Setting time offset from file %s, offset %llu\n", ats_path.c_str(), (unsigned long long) offset);
		DataManager::SetValue("tw_qcom_ats_offset", (unsigned long long) offset, 1);
		fixed = true;
	}

	if (!fixed) {
		// Failed to get offset from ats file, check twrp settings
		unsigned long long value;
		if (DataManager::GetValue("tw_qcom_ats_offset", value) < 0) {
			return;
		} else {
			offset = (uint64_t) value;
			LOGINFO("TWFunc::Fixup_Time: Setting time offset from twrp setting file, offset %llu\n", (unsigned long long) offset);
			// Do not consider the settings file as a definitive answer, keep fixed=false so next run will try ats files again
		}
	}

	gettimeofday(&tv, NULL);

	tv.tv_sec += offset/1000;
#ifdef TW_CLOCK_OFFSET
// Some devices are even quirkier and have ats files that are offset from the actual time
	tv.tv_sec = tv.tv_sec + TW_CLOCK_OFFSET;
#endif
	tv.tv_usec += (offset%1000)*1000;

	while (tv.tv_usec >= 1000000)
	{
		++tv.tv_sec;
		tv.tv_usec -= 1000000;
	}

	settimeofday(&tv, NULL);

	LOGINFO("TWFunc::Fixup_Time: Date and time corrected: %s\n", TWFunc::Get_Current_Date().c_str());
#endif
}

std::vector<std::string> TWFunc::Split_String(const std::string& str, const std::string& delimiter, bool removeEmpty)
{
	std::vector<std::string> res;
	size_t idx = 0, idx_last = 0;

	while (idx < str.size())
	{
		idx = str.find_first_of(delimiter, idx_last);
		if (idx == std::string::npos)
			idx = str.size();

		if (idx-idx_last != 0 || !removeEmpty)
			res.push_back(str.substr(idx_last, idx-idx_last));

		idx_last = idx + delimiter.size();
	}

	return res;
}

bool TWFunc::Create_Dir_Recursive(const std::string& path, mode_t mode, uid_t uid, gid_t gid)
{
	std::vector<std::string> parts = Split_String(path, "/");
	std::string cur_path;
	struct stat info;
	for (size_t i = 0; i < parts.size(); ++i)
	{
		cur_path += "/" + parts[i];
		if (stat(cur_path.c_str(), &info) < 0 || !S_ISDIR(info.st_mode))
		{
			if (mkdir(cur_path.c_str(), mode) < 0)
				return false;
			chown(cur_path.c_str(), uid, gid);
		}
	}
	return true;
}

int TWFunc::Set_Brightness(std::string brightness_value)
{
	int result = -1;
	std::string secondary_brightness_file;

	if (DataManager::GetIntValue("tw_has_brightnesss_file")) {
		LOGINFO("TWFunc::Set_Brightness: Setting brightness control to %s\n", brightness_value.c_str());
		result = TWFunc::write_to_file(DataManager::GetStrValue("tw_brightness_file"), brightness_value);
		DataManager::GetValue("tw_secondary_brightness_file", secondary_brightness_file);
		if (!secondary_brightness_file.empty()) {
			LOGINFO("TWFunc::Set_Brightness: Setting secondary brightness control to %s\n", brightness_value.c_str());
			TWFunc::write_to_file(secondary_brightness_file, brightness_value);
		}
	}
	return result;
}

bool TWFunc::Toggle_MTP(bool enable) {
#ifdef TW_HAS_MTP
	static int was_enabled = false;

	if (enable && was_enabled) {
		if (!PartitionManager.Enable_MTP())
			PartitionManager.Disable_MTP();
	} else {
		was_enabled = DataManager::GetIntValue("tw_mtp_enabled");
		PartitionManager.Disable_MTP();
		usleep(500);
	}
	return was_enabled;
#else
	return false;
#endif
}

void TWFunc::SetPerformanceMode(bool mode) {
	if (mode) {
		property_set("recovery.perf.mode", "1");
	} else {
		property_set("recovery.perf.mode", "0");
	}
	// Some time for events to catch up to init handlers
	usleep(500000);
}

std::string TWFunc::to_string(unsigned long value) {
	std::ostringstream os;
	os << value;
	return os.str();
}

void TWFunc::Disable_Stock_Recovery_Replace(void) {
	PartitionManager.Mount_By_Path("/vendor", false);
	PartitionManager.Mount_By_Path(PartitionManager.Get_Android_Root_Path(), false);
		// Disable flashing of stock recovery
		if (DataManager::GetIntValue(PB_ADVANCED_STOCK_REPLACE) == 1) {
			  if (Path_Exists("/system/bin/install-recovery.sh"))
				     rename("/system/bin/install-recovery.sh", "/system/bin/wlfx0install-recoverybak0xwlf");    
			if (Path_Exists("/system/etc/install-recovery.sh"))
				  rename("/system/etc/install-recovery.sh", "/system/etc/wlfx0install-recoverybak0xwlf");
			if (Path_Exists("/system/etc/recovery-resource.dat"))
				    rename("/system/etc/recovery-resource.dat", "/system/etc/wlfx0recovery-resource0xwlf");
			  if (Path_Exists("/system/vendor/bin/install-recovery.sh")) 
				     rename("/system/vendor/bin/install-recovery.sh", "/system/vendor/bin/wlfx0install-recoverybak0xwlf");    
			if (Path_Exists("/system/vendor/etc/install-recovery.sh"))
				  rename("/system/vendor/etc/install-recovery.sh", "/system/vendor/etc/wlfx0install-recoverybak0xwlf");
			if (Path_Exists("/system/vendor/etc/recovery-resource.dat"))
				    rename("/system/vendor/etc/recovery-resource.dat", "/system/vendor/etc/wlfx0recovery-resource0xwlf");
			  if (Path_Exists("/vendor/bin/install-recovery.sh")) 
				     rename("/vendor/bin/install-recovery.sh", "/vendor/bin/wlfx0install-recoverybak0xwlf");    
			if (Path_Exists("/vendor/etc/install-recovery.sh"))
				  rename("/vendor/etc/install-recovery.sh", "/vendor/etc/wlfx0install-recoverybak0xwlf");
			if (Path_Exists("/vendor/etc/recovery-resource.dat"))
				    rename("/vendor/etc/recovery-resource.dat", "/vendor/etc/wlfx0recovery-resource0xwlf");
			if (TWFunc::Path_Exists("/system/recovery-from-boot.p")) {
				rename("/system/recovery-from-boot.p", "/system/wlfx0recovery-from-bootbak0xwlf");
		        	sync();
			}		
		}
		if (PartitionManager.Is_Mounted_By_Path(PartitionManager.Get_Android_Root_Path()))
			PartitionManager.UnMount_By_Path(PartitionManager.Get_Android_Root_Path(), false);
		if (PartitionManager.Is_Mounted_By_Path("/vendor"))
			PartitionManager.UnMount_By_Path("/vendor", false);
}

unsigned long long TWFunc::IOCTL_Get_Block_Size(const char* block_device) {
	unsigned long block_device_size;
	int ret = 0;

	int fd = open(block_device, O_RDONLY);
	if (fd < 0) {
		LOGINFO("Find_Partition_Size: Failed to open '%s', (%s)\n", block_device, strerror(errno));
	} else {
		ret = ioctl(fd, BLKGETSIZE, &block_device_size);
		close(fd);
		if (ret) {
			LOGINFO("Find_Partition_Size: ioctl error: (%s)\n", strerror(errno));
		} else {
			return (unsigned long long)(block_device_size) * 512LLU;
		}
	}
	return 0;
}

bool TWFunc::CheckWord(std::string filename, std::string search) {
    std::string line;
    ifstream File;
    File.open (filename);
    if(File.is_open()) {
        while(!File.eof()) {
            getline(File,line);
            if (line.find(search) != std::string::npos)
             return true;
        }
        File.close();
    }
    return false;
}

void TWFunc::Replace_Word_In_File(std::string file_path, std::string search) {
  std::string contents_of_file, local, renamed = file_path + ".wlfx";
  if (TWFunc::Path_Exists(renamed))
  unlink(renamed.c_str());
  std::rename(file_path.c_str(), renamed.c_str());
  std::ifstream old_file(renamed.c_str());
  std::ofstream new_file(file_path.c_str());
  size_t start_pos, end_pos, pos;
  while (std::getline(old_file, contents_of_file)) {
  start_pos = 0; pos = 0;
  end_pos = search.find(";", start_pos);
  while (end_pos != string::npos && start_pos < search.size()) {
   local = search.substr(start_pos, end_pos - start_pos);
   if (contents_of_file.find(local) != string::npos) {
      while((pos = contents_of_file.find(local, pos)) != string::npos)
      contents_of_file.replace(pos, local.length(), "");
     }
     start_pos = end_pos + 1;
     end_pos = search.find(";", start_pos);
    }
      new_file << contents_of_file << '\n';
  }
  unlink(renamed.c_str());
  chmod(file_path.c_str(), 0644);  
}


void TWFunc::Replace_Word_In_File(string file_path, string search, string word) {
  std::string renamed = file_path + ".wlfx";
  std::string contents_of_file;
  if (TWFunc::Path_Exists(renamed))
  unlink(renamed.c_str());
  std::rename(file_path.c_str(), renamed.c_str());
  std::ifstream old_file(renamed.c_str());
  std::ofstream new_file(file_path.c_str());
  while (std::getline(old_file, contents_of_file)) {
   if (contents_of_file.find(search) != std::string::npos) {
      size_t pos = 0;
      while((pos = contents_of_file.find(search, pos)) != std::string::npos) {
      contents_of_file.replace(pos, search.length(), word);
      pos += word.length();
      }
     }
      new_file << contents_of_file << '\n';
  }
  unlink(renamed.c_str());
}


void TWFunc::Set_New_Ramdisk_Property(string prop, bool enable) {
if (TWFunc::CheckWord(default_prop, prop)) {
if (enable) {
string expected_value = prop + "=0";
prop += "=1";
TWFunc::Replace_Word_In_File(default_prop, expected_value, prop);
} else {
string expected_value = prop + "=1";
prop += "=0";
TWFunc::Replace_Word_In_File(default_prop, expected_value, prop);
}
} else {
ofstream File(default_prop.c_str(), ios_base::app | ios_base::out);  
if (File.is_open()) {
if (enable)
prop += "=1";
else
prop += "=0";
File << prop << endl;
File.close();
}
}
}

string TWFunc::Load_File(string extension) {
string line, path = split_img + extension;
ifstream File;
File.open (path);
if(File.is_open()) {
getline(File,line);
File.close();
}
return line;
}

bool TWFunc::Unpack_Image(string mount_point, bool part) {
string null;
usleep(500);
if (TWFunc::Path_Exists(tmp))
TWFunc::removeDir(tmp, false);
//if (!TWFunc::Recursive_Mkdir(ramdisk))
//return fals
if (!TWFunc::Recursive_Mkdir(split_img))
return false;
string Command = "cd " + split_img + " && /sbin/magiskboot --unpack -h ";
if (part) {
	TWPartition* Partition = PartitionManager.Find_Partition_By_Path(mount_point);
	if (Partition == NULL || Partition->Current_File_System != "emmc") {
		LOGERR("TWFunc::Unpack_Image: Partition don't exist or isn't emmc");
		return false;
	}
	Read_Write_Specific_Partition("/tmp/pb/boot.img", mount_point, true);
	Command += "/tmp/pb/boot.img";
}
else {
	Command += mount_point;
}
if (TWFunc::Exec_Cmd(Command) != 0) {
	TWFunc::removeDir(tmp, false);
	return false;
}
DIR* dir;
struct dirent* der;
dir = opendir(split_img.c_str());
while((der = readdir(dir)) != NULL)
{
	Command = der->d_name;
	if (Command.find("extra") != string::npos || Command.find("dtb") != string::npos)
	{
		dtb = split_img + Command;
	}
	if (Command.find("ramdisk") != string::npos)
	{
		ram = split_img + Command;
	}
}
closedir (dir);
if (ram.find("ramdisk") != string::npos) {
	return Unpack_Repack_ramdisk(false);
}
else
	LOGINFO("Unpack_Image: Doesn't have Ramdisk");
return true;
}

bool TWFunc::Unpack_Repack_ramdisk(bool repack) {
	string null = "";
	if (!repack) {
		if (!TWFunc::Recursive_Mkdir(ramdisk))
			return false;
		if (TWFunc::Exec_Cmd("cd " + ramdisk + "; cpio -i < " + ram, null) == 0)
			unlink(ram.c_str());
		else
			return false;
	}
	else {
		Exec_Cmd("cd " + ramdisk + "; find | cpio -o -H newc > " + split_img + "ramdisk.cpio", null);
		if (!Path_Exists(split_img + "ramdisk.cpio"))
		{
			LOGINFO("Failed to backup Cpio");
			return false;
		}
	}
	return true;
}

bool TWFunc::Repack_Image(string mount_point, bool part) {
string null, Command;
usleep(1000);
DIR* dir;
dir = opendir(split_img.c_str());
if (dir == NULL)
{
	LOGINFO("Unable to open '%s'\n", split_img.c_str());
	return false;
}
closedir(dir);
if (ram.find("ramdisk") != string::npos && !Unpack_Repack_ramdisk(true)) {
	return false;
}
Command = "cd " + split_img + " && /sbin/magiskboot --repack ";
if (part) {
	Command += "/tmp/pb/boot.img";
}
else {
	Command += mount_point;
}
if (TWFunc::Exec_Cmd(Command, null) != 0)
{
	TWFunc::removeDir(tmp, false);
	return false;
}
if (part)
Read_Write_Specific_Partition(split_img + "new-boot.img", mount_point, false);
else {
	unlink(mount_point.c_str());
	string cmdd = "mv " + split_img +"new-boot.img " + mount_point;
	if (TWFunc::Exec_Cmd(cmdd, null) != 0)
		return false;
}
TWFunc::removeDir(tmp, false);
return true;
}

bool TWFunc::Symlink(string src, string dest)
{
	string null;
	if (TWFunc::Path_Exists(dest + "/" + TWFunc::Get_Filename(src)))
	{
		LOGINFO("Symlink Exists : '%s'\n", (dest + "/" + TWFunc::Get_Filename(src)).c_str());
		return false;
	}
	if (TWFunc::Path_Exists(src))
	{
		if(TWFunc::Path_Exists(dest) || TWFunc::Recursive_Mkdir(dest))
		{
			if (TWFunc::Exec_Cmd("cd " + dest + " && ln -s " + src, null) == 0)
			{
				LOGINFO("Symlink Created : '%s'\n", (dest + "/" + TWFunc::Get_Filename(src)).c_str());
			}
			else {
				LOGINFO("Symlink Creation failed \n");
				return false;
			}
		}
		else
		{
			LOGINFO("Symlink: either dest not preset or not created\n");
			return false;
		}
	}
	else
	{
		LOGINFO("Source Dir : '%s' is not Exists\n", src.c_str());
		return false;
	}
	return true;
}

bool TWFunc::check_system_root() {
	string out;
	if(!PartitionManager.Is_Mounted_By_Path(PartitionManager.Get_Android_Root_Path()))
	        PartitionManager.Mount_By_Path(PartitionManager.Get_Android_Root_Path(), false);
	if (TWFunc::Path_Exists(PartitionManager.Get_Android_Root_Path() + "/init.rc"))
		return true;
	else if (TWFunc::Exec_Cmd("grep -q \'/system_root\' /proc/mounts", out) == 0 || TWFunc::Exec_Cmd("grep \' / \' /proc/mounts | grep -qv rootfs", out) == 0)
		return true;
	return false;
}

int TWFunc::check_encrypt_status() {
	string out;
	int status = 0;
	TWPartition *part = PartitionManager.Find_Partition_By_Path("/data");
	if (DataManager::GetIntValue(TW_IS_DECRYPTED)) {
		if (part != NULL)
			part->Mount(false);
	}
	if (TWFunc::Exec_Cmd("grep /data /proc/mounts | grep -q dm-", out) == 0)
		status += 1;
	if (TWFunc::Path_Exists("/data/unencrypted") || DataManager::GetIntValue(TW_IS_FBE))
		status += 2;
	if ((DataManager::GetIntValue(TW_IS_FBE) && (status == 1 || status == 3)) || (status == 3 && TWFunc::Exec_Cmd("grep /data /proc/mounts | grep -i f2fs", out) == 0))
		status = 2;
	part->UnMount(false);
	return status;
}

static bool Patch_AVBDM_Verity() {
	bool status = false, def = false;
	DIR* d;
	DIR* d1 = nullptr;
	struct dirent* de;
	int stat = 0;
	string path, fstab = "", cmp, remove = "verify,;,verify;verify;,avb;avb;avb,;support_scfs,;,support_scfs;support_scfs;";
	if (ram.find("ramdisk") != string::npos) {
		d = opendir(ramdisk.c_str());
		if (d == NULL)
		{
			LOGINFO("Unable to open '%s'\n", ramdisk.c_str());
			return false;
		}
		while ((de = readdir(d)) != NULL)
		{
			cmp = de->d_name;
			path = ramdisk + cmp;
			if (cmp.find("fstab.") != string::npos)
			{
				gui_msg(Msg("pb_fstab=Detected fstab: '{1}'")(cmp));
				LOGINFO("Fstab Found at '%s'\n", ramdisk.c_str());
				stat = 1;
				if (!status)
				{
					if (TWFunc::CheckWord(path, "verify")
					|| TWFunc::CheckWord(path, "support_scfs")
					|| TWFunc::CheckWord(path, "avb"))
						status = true;
				}
				TWFunc::Replace_Word_In_File(path, remove);
			}
			if (cmp == "default.prop")
			{
				if (TWFunc::CheckWord(path, "ro.config.dmverity="))
				{
					if (TWFunc::CheckWord(path, "ro.config.dmverity=true"))
						TWFunc::Replace_Word_In_File(path, "ro.config.dmverity=true;", "ro.config.dmverity=false");
				}
				else
				{
					ofstream File(path.c_str(), ios_base::app | ios_base::out);  
					if (File.is_open())
					{
						def = true;
						File << "ro.config.dmverity=false" << endl;
						File.close();
					}
				}
			}
		}
		closedir (d);
	}

	if (stat == 0)
	{
		if(trb_en == 1 || PartitionManager.Mount_By_Path("/vendor", false))
		{
			d1 = opendir(fstab2.c_str());
			stat = 2;
		}
		else
		{
			PartitionManager.Mount_By_Path(PartitionManager.Get_Android_Root_Path(), false);
			d1 = opendir(fstab1.c_str());
			stat = 1;
		}
		if (d1 == NULL)
		{
			if(stat == 2)
				LOGINFO("Unable to open '%s'\n", fstab2.c_str());
			else if(stat == 1)
				LOGINFO("Unable to open '%s'\n", fstab1.c_str());
			return false;
		}
		while ((de = readdir(d1)) != NULL)
		{
			cmp = de->d_name;
			if (stat == 2)
				path = fstab2 + "/" + cmp;
			else if (stat == 1)
				path = fstab1 + "/" + cmp;
			if (cmp.find("fstab.") != string::npos)
			{
				fstab = cmp;
				gui_msg(Msg("pb_fstab=Detected fstab: '{1}'")(cmp));
				if (stat == 2)
					LOGINFO("Fstab Found at '%s'\n", fstab2.c_str());
				else if (stat == 1)
					LOGINFO("Fstab Found at '%s'\n", fstab1.c_str());
				if (!status)
				{
					if (TWFunc::CheckWord(path, "verify")
					|| TWFunc::CheckWord(path, "support_scfs")
					|| TWFunc::CheckWord(path, "avb"))
						status = true;
				}
				TWFunc::Replace_Word_In_File(path, remove);

			}
			if (cmp == "default.prop")
			{
				def = true;
				if (TWFunc::CheckWord(path, "ro.config.dmverity="))
				{
					if (TWFunc::CheckWord(path, "ro.config.dmverity=true"))
						TWFunc::Replace_Word_In_File(path, "ro.config.dmverity=true;", "ro.config.dmverity=false");
				}
				else
				{
					ofstream File(path.c_str(), ios_base::app | ios_base::out);  
					if (File.is_open())
					{
						File << "ro.config.dmverity=false" << endl;
						File.close();
					}			
				}
			}
		}
	        closedir (d1);
		chmod(fstab.c_str(), 0644);
		//additional check for default.prop
		if(!def) {
			if (PartitionManager.Is_Mounted_By_Path("/vendor")) 
				path = fstab2 + "/default.prop" ;
			else
				path = fstab1 + "/default.prop";
			if (TWFunc::CheckWord(path, "ro.config.dmverity="))
			{
				if (TWFunc::CheckWord(path, "ro.config.dmverity=true"))
					TWFunc::Replace_Word_In_File(path, "ro.config.dmverity=true;", "ro.config.dmverity=false");
			}
		}
		//end
	}
	return status;
}

bool TWFunc::Patch_DM_Verity() {
	bool status = false;
	string firmware_key = ramdisk + "sbin/firmware_key.cer";
	string null, sys_rt = TWFunc::check_system_root() ? "true" : "false";
	if (sys_rt == "false")
		status = Patch_AVBDM_Verity();

	if (TWFunc::Path_Exists(ramdisk + "verity_key")) {
		gui_msg(Msg("pb_unlink=Unlinking: '{1}'")("verity_key"));
		unlink((ramdisk + "verity_key").c_str());
	}
	LOGINFO("DTB Found at '%s'\n", dtb.c_str());
	setenv("KEEPVERITY", sys_rt.c_str(), true);

	if (TWFunc::Path_Exists(firmware_key))
	{
		gui_msg(Msg("pb_unlink=Unlinking: '{1}'")("firmware_key.cer"));
		unlink(firmware_key.c_str());
	}

	if(PartitionManager.Is_Mounted_By_Path("/vendor"))
		PartitionManager.UnMount_By_Path("/vendor", false);
	else if(PartitionManager.Is_Mounted_By_Path("/cust"))
		PartitionManager.UnMount_By_Path("/cust", false);
	if(PartitionManager.Is_Mounted_By_Path(PartitionManager.Get_Android_Root_Path()))
	        PartitionManager.UnMount_By_Path(PartitionManager.Get_Android_Root_Path(), false);
	return status;
}            

bool TWFunc::Patch_Forced_Encryption()
{
	string path, null, fstab = "", cmp, command = "";
	command = "sed -i \"";
	int stat = 0;
	string remove[] = {"forceencrypt=", "forcefdeorfbe=", "fileencryption="};
	for(int i=0;i<=2;i++)
	{
		if(i < 2)
			command += "s|" + remove[i] + "|encryptable=|g; ";
		else
			command += "s|" + remove[i] + "|encryptable=|g;\"";
	}

	bool status = false;
	int encryption;
	DataManager::GetValue(PB_DISABLE_DM_VERITY, encryption);
	DIR* d;
	DIR* d1 = nullptr;
	struct dirent* de;
	if (ram.find("ramdisk") != string::npos) {
		d = opendir(ramdisk.c_str());
		if (d == NULL)
		{
			LOGINFO("Unable to open '%s'\n", ramdisk.c_str());
			return false;
		}
		while ((de = readdir(d)) != NULL)
		{
			cmp = de->d_name;
			path = ramdisk + cmp;
			if (cmp.find("fstab.") != string::npos)
			{
				if (encryption != 1)
				{
					gui_msg(Msg("pb_fstab=Detected fstab: '{1}'")(cmp));
					LOGINFO("Fstab Found at '%s'\n", ramdisk.c_str());
				}
				stat = 1;
				if (!status)
				{
					if (TWFunc::Exec_Cmd(command + " " + path, null) == 0)
						if(null.empty())
						{
							command="";
							status = true;
						}
				}
			}
		}
		closedir (d);
	}
	if (stat == 0 || ram.find("ramdisk") != string::npos)
	{
		if(trb_en == 1 || PartitionManager.Mount_By_Path("/vendor", false))
		{
			//PartitionManager.Mount_By_Path("/vendor", false);
			d1 = opendir(fstab2.c_str());
			stat = 2;
		}
		else
		{
			PartitionManager.Mount_By_Path(PartitionManager.Get_Android_Root_Path(), false);
			d1 = opendir(fstab1.c_str());
			stat = 1;
		}
		if (d1 == NULL)
		{
			if(stat == 2)
				LOGINFO("Unable to open '%s'\n", fstab2.c_str());
			else if(stat == 1)
				LOGINFO("Unable to open '%s'\n", fstab1.c_str());
			return false;
		}
		while ((de = readdir(d1)) != NULL)
		{
			cmp = de->d_name;
			if (stat == 2)
				path = fstab2 + "/" + cmp;
			else if (stat == 1)
				path = fstab1 + "/" + cmp;
			if (cmp.find("fstab.") != string::npos)
			{
				fstab = cmp;
			        if (encryption != 1)
				{
					gui_msg(Msg("pb_fstab=Detected fstab: '{1}'")(cmp));
				if (stat == 2)
					LOGINFO("Fstab Found at '%s'\n", fstab2.c_str());
				else if (stat == 1)
					LOGINFO("Fstab Found at '%s'\n", fstab1.c_str());
				}
				if (!status)
				{
					if (TWFunc::Exec_Cmd(command + " " + path, null) == 0)
					{
						if(null.empty())
						{
							command="";
							status = true;
						}
					}
				}
		       }
	        }
	        closedir (d1);
		chmod(fstab.c_str(), 0644);

	}
	if(PartitionManager.Is_Mounted_By_Path("/vendor"))
		PartitionManager.UnMount_By_Path("/vendor", false);
	else if(PartitionManager.Is_Mounted_By_Path("/cust"))
		PartitionManager.UnMount_By_Path("/cust", false);
	if(PartitionManager.Is_Mounted_By_Path(PartitionManager.Get_Android_Root_Path()))
	        PartitionManager.UnMount_By_Path(PartitionManager.Get_Android_Root_Path(), false);
	return status;
}
    
void TWFunc::Deactivation_Process(void)
{
	string out;
	if(PartitionManager.Is_Mounted_By_Path("/vendor"))
		PartitionManager.UnMount_By_Path("/vendor", false);
	else if(PartitionManager.Is_Mounted_By_Path("/cust"))
		PartitionManager.UnMount_By_Path("/cust", false);
	if(PartitionManager.Is_Mounted_By_Path(PartitionManager.Get_Android_Root_Path()))
	        PartitionManager.UnMount_By_Path(PartitionManager.Get_Android_Root_Path(), false);
	if (DataManager::GetIntValue(PB_DISABLE_DM_VERITY) == 1) {
		if (!Unpack_Image("/boot")) {
			LOGINFO("Deactivation_Process: Unable to unpack image\n");
			return;
		}
		gui_msg(Msg(msg::kProcess, "pb_run_process=Starting '{1}' process")("PitchBlack"));
		DataManager::GetValue(TRB_EN, trb_en);
		if (TWFunc::check_encrypt_status() != 0 && DataManager::GetIntValue(PB_ENABLE_ADVANCE_ENCRY) == 0) {
			gui_msg(Msg(msg::kHighlight, "pb_ecryption_leave=Device Encrypted Leaving Forceencrypt"));
			setenv("KEEPFORCEENCRYPT", "true", true);
			DataManager::SetValue(PB_DISABLE_FORCED_ENCRYPTION, 0);
		}
		else {
			setenv("KEEPFORCEENCRYPT", "false", true);
			DataManager::SetValue(PB_DISABLE_FORCED_ENCRYPTION, 1);
		}

		if (DataManager::GetIntValue(PB_DISABLE_DM_VERITY) == 1) {
			if (!Patch_DM_Verity())
				gui_print_color("warning", "DM-Verity is not enabled\n");
		}

		if (DataManager::GetIntValue(PB_DISABLE_FORCED_ENCRYPTION) == 1) {
			if (!Patch_Forced_Encryption())
				gui_print_color("warning", "Forced Encryption is not enabled\n");
		}

		gui_msg(Msg("pb_patching=Patching: '{1}'")("ramdisk"));
		TWFunc::Exec_Cmd("cd /tmp/pb/split_img && /sbin/magiskboot cpio ramdisk.cpio patch", out);
		gui_msg(Msg("pb_patching=Patching: '{1}'")("dtb"));
		TWFunc::Exec_Cmd("cd /tmp/pb/split_img && /sbin/magiskboot dtb " + dtb + " patch", out);
		unsetenv("KEEPFORCEENCRYPT");
		unsetenv("KEEPVERITY");
		out="";
		if (!Repack_Image("/boot")) {
			gui_msg(Msg(msg::kError, "pb_run_process_fail=Unable to finish '{1}' process")("PitchBlack"));
			return;
		}

		if (DataManager::GetIntValue("pb_req_patch_avb2") == 1) {
			TWPartition* Partition = PartitionManager.Find_Partition_By_Path("/boot");
			if(PBFunc::patchAVB(Partition->Actual_Block_Device.c_str()) == 0) {
				gui_msg(Msg("pb_patch_avb2=Patched AVB2.0"));
			} else {
				gui_msg(Msg("pb_patch_avb_no=AVB2.0 not available"));
			}
		}

		gui_msg(Msg(msg::kProcess, "pb_run_process_done=Finished '{1}' process")("PitchBlack"));
		return;
	}
}

void TWFunc::Read_Write_Specific_Partition(string path, string partition_name, bool backup) {
	TWPartition* Partition = PartitionManager.Find_Partition_By_Path(partition_name);
	if (Partition == NULL || Partition->Current_File_System != "emmc") {
	LOGERR("Read_Write_Specific_Partition: Unable to find %s\n", partition_name.c_str());
	return;
	}
	string Read_Write, oldfile, null;
	unsigned long long Remain, Remain_old;
	oldfile = path + ".bak";
	if (backup) {
#ifdef PB_FORCE_DD_FLASH
		Read_Write = "dd if=" + Partition->Actual_Block_Device + " of=" + path + " bs=6291456 count=1";
#else
		Read_Write = "dump_image " + Partition->Actual_Block_Device + " " + path;
#endif
	}
	else {
#ifdef PB_FORCE_DD_FLASH
		Read_Write = "dd if=" + path + " of=" + Partition->Actual_Block_Device;
#else
		Read_Write = "flash_image " + Partition->Actual_Block_Device + " " + path;
#endif
		if (TWFunc::Path_Exists(oldfile)) {
			Remain_old = TWFunc::Get_File_Size(oldfile);
			Remain = TWFunc::Get_File_Size(path);
			if (Remain_old < Remain) {
				return;
			}
		}
		TWFunc::Exec_Cmd(Read_Write, null);
		return;
	}
	if (TWFunc::Path_Exists(path))
	unlink(path.c_str());
	TWFunc::Exec_Cmd(Read_Write, null);
	return;
}

void TWFunc::copy_logcat_log(string curr_storage) {
	std::string logcatDst = curr_storage + "/logcat.log";
	std::string logcatCmd = "/sbin/logcat -d";

	std::string result;
	Exec_Cmd(logcatCmd, result);
	write_to_file(logcatDst, result);
	gui_msg(Msg("copy_logcat_log=Copied logcat log to {1}")(logcatDst));
	tw_set_default_metadata(logcatDst.c_str());
}

void TWFunc::copy_kernel_log(string curr_storage) {
	std::string dmesgDst = curr_storage + "/dmesg.log";
	std::string dmesgCmd = "/sbin/dmesg";

	std::string result;
	Exec_Cmd(dmesgCmd, result);
	write_to_file(dmesgDst, result);
	gui_msg(Msg("copy_kernel_log=Copied kernel log to {1}")(dmesgDst));
	tw_set_default_metadata(dmesgDst.c_str());
}

void TWFunc::create_fingerprint_file(string file_path, string fingerprint) {
		if (TWFunc::Path_Exists(file_path))
		unlink(file_path.c_str());
	    ofstream file;
        file.open (file_path.c_str());
        file << fingerprint;
        file.close();
	    tw_set_default_metadata(file_path.c_str());
}

bool TWFunc::Verify_Incremental_Package(string fingerprint, string metadatafp, string metadatadevice) {
string brand_property = "ro.product.brand";
string androidversion = TWFunc::System_Property_Get("ro.build.version.release");
string buildpropbrand = TWFunc::System_Property_Get(brand_property);
string buildid = TWFunc::System_Property_Get("ro.build.id");
string buildincremental = TWFunc::System_Property_Get("ro.build.version.incremental");
string buildtags = TWFunc::System_Property_Get("ro.build.tags");
string buildtype = TWFunc::System_Property_Get("ro.build.type");
if (!metadatadevice.empty() && metadatadevice.size() >= 4 && !fingerprint.empty() && fingerprint.size() > PB_MIN_EXPECTED_FP_SIZE && fingerprint.find(metadatadevice) == std::string::npos) {
	LOGINFO("OTA_ERROR: %s\n", metadatadevice.c_str());
    LOGINFO("OTA_ERROR: %s\n", fingerprint.c_str());
    return false;
	}
	if (!metadatadevice.empty() && metadatadevice.size() >= 4 && !metadatafp.empty() && metadatafp.size() > PB_MIN_EXPECTED_FP_SIZE && metadatafp.find(metadatadevice) == std::string::npos) {
	LOGINFO("OTA_ERROR: %s\n", metadatadevice.c_str());
    LOGINFO("OTA_ERROR: %s\n", metadatafp.c_str());
    return false;
	}

if (!fingerprint.empty() && fingerprint.size() > PB_MIN_EXPECTED_FP_SIZE) {
   if (!buildpropbrand.empty() && buildpropbrand.size() >= 3) {
        if (fingerprint.find(buildpropbrand) == std::string::npos)
        buildpropbrand[0] = toupper(buildpropbrand[0]);
        if (fingerprint.find(buildpropbrand) == std::string::npos)
        buildpropbrand[0] = tolower(buildpropbrand[0]);
        if (fingerprint.find(buildpropbrand) == std::string::npos) {
        LOGINFO("OTA_ERROR: %s\n", buildpropbrand.c_str());
        LOGINFO("OTA_ERROR: %s\n", fingerprint.c_str());
        return false;
        }
		} else {
        char brand[PROPERTY_VALUE_MAX];
        property_get(brand_property.c_str(), brand, "");
        std::string brandstr = brand;
        if (!brandstr.empty() && brandstr.size() >= 3 && fingerprint.find(brandstr) == std::string::npos) {
        brandstr[0] = toupper(brandstr[0]);
        if (!brandstr.empty() && brandstr.size() >= 3 && fingerprint.find(brandstr) == std::string::npos)
        brandstr[0] = tolower(brandstr[0]);
        if (!brandstr.empty() && brandstr.size() >= 3 && fingerprint.find(brandstr) == std::string::npos) {
        LOGINFO("OTA_ERROR: %s\n", brandstr.c_str());
        LOGINFO("OTA_ERROR: %s\n", fingerprint.c_str());
        return false;
        }
		}
	   }
	if (!androidversion.empty() && androidversion.size() >= 3) {
	if (fingerprint.find(androidversion) == std::string::npos) {
		LOGINFO("OTA_ERROR: %s\n", androidversion.c_str());
        LOGINFO("OTA_ERROR: %s\n", fingerprint.c_str());
        return false;
        }
        }
        if (!buildid.empty() && buildid.size() >= 3) {
	    if (fingerprint.find(buildid) == std::string::npos) {
		LOGINFO("OTA_ERROR: %s\n", buildid.c_str());
        LOGINFO("OTA_ERROR: %s\n", fingerprint.c_str());
        return false;
        }
        }
        if (!buildincremental.empty() && buildincremental.size() >= 3) {
	    if (fingerprint.find(buildincremental) == std::string::npos) {
		LOGINFO("OTA_ERROR: %s\n", buildincremental.c_str());
        LOGINFO("OTA_ERROR: %s\n", fingerprint.c_str());
        return false;
        }
        }
        if (!buildtags.empty() && buildtags.size() >= 5) {
	    if (fingerprint.find(buildtags) == std::string::npos) {
		LOGINFO("OTA_ERROR: %s\n", buildtags.c_str());
        LOGINFO("OTA_ERROR: %s\n", fingerprint.c_str());
        return false;
        }
        }
        if (!buildtype.empty() && buildtype.size() >= 4) {
        if (fingerprint.find(buildtype) == std::string::npos) {
		LOGINFO("OTA_ERROR: %s\n", buildtype.c_str());
        LOGINFO("OTA_ERROR: %s\n", fingerprint.c_str());
        return false;
        }
        }
	}
	if (!metadatafp.empty() && metadatafp.size() > PB_MIN_EXPECTED_FP_SIZE) {
   if (!buildpropbrand.empty() && buildpropbrand.size() >= 3) {
   if (metadatafp.find(buildpropbrand) == std::string::npos)
        buildpropbrand[0] = toupper(buildpropbrand[0]);
        if (metadatafp.find(buildpropbrand) == std::string::npos)
        buildpropbrand[0] = tolower(buildpropbrand[0]);
        if (metadatafp.find(buildpropbrand) == std::string::npos) {
        LOGINFO("OTA_ERROR: %s\n", buildpropbrand.c_str());
        LOGINFO("OTA_ERROR: %s\n", metadatafp.c_str());
        return false;
        }
		} else {
        char brandvalue[PROPERTY_VALUE_MAX];
        property_get(brand_property.c_str(), brandvalue, "");
        std::string brandstrtwo = brandvalue;
        if (!brandstrtwo.empty() && brandstrtwo.size() >= 3 && metadatafp.find(brandstrtwo) == std::string::npos) {
        brandstrtwo[0] = toupper(brandstrtwo[0]);
        if (!brandstrtwo.empty() && brandstrtwo.size() >= 3 && metadatafp.find(brandstrtwo) == std::string::npos)
        brandstrtwo[0] = tolower(brandstrtwo[0]);
        if (!brandstrtwo.empty() && brandstrtwo.size() >= 3 && metadatafp.find(brandstrtwo) == std::string::npos) {
        LOGINFO("OTA_ERROR: %s\n", brandstrtwo.c_str());
        LOGINFO("OTA_ERROR: %s\n", metadatafp.c_str());
        return false;
        }
		}
	   }
	if (!androidversion.empty() && androidversion.size() >= 3) {
	if (metadatafp.find(androidversion) == std::string::npos) {
		LOGINFO("OTA_ERROR: %s\n", androidversion.c_str());
        LOGINFO("OTA_ERROR: %s\n", metadatafp.c_str());
        return false;
        }
        }
        if (!buildid.empty() && buildid.size() >= 3) {
	    if (metadatafp.find(buildid) == std::string::npos) {
		LOGINFO("OTA_ERROR: %s\n", buildid.c_str());
        LOGINFO("OTA_ERROR: %s\n", metadatafp.c_str());
        return false;
        }
        }
        if (!buildincremental.empty() && buildincremental.size() >= 3) {
	    if (metadatafp.find(buildincremental) == std::string::npos) {
		LOGINFO("OTA_ERROR: %s\n", buildincremental.c_str());
        LOGINFO("OTA_ERROR: %s\n", metadatafp.c_str());
        return false;
        }
        }
        if (!buildtags.empty() && buildtags.size() >= 5) {
	    if (metadatafp.find(buildtags) == std::string::npos) {
		LOGINFO("OTA_ERROR: %s\n", buildtags.c_str());
        LOGINFO("OTA_ERROR: %s\n", metadatafp.c_str());
        return false;
        }
        }
        if (!buildtype.empty() && buildtype.size() >= 4) {
        if (metadatafp.find(buildtype) == std::string::npos) {
		LOGINFO("OTA_ERROR: %s\n", buildtype.c_str());
        LOGINFO("OTA_ERROR: %s\n", metadatafp.c_str());
        return false;
        }
        }
	}
	
	if (!metadatafp.empty() && metadatafp.size() > PB_MIN_EXPECTED_FP_SIZE && !fingerprint.empty() && fingerprint.size() > PB_MIN_EXPECTED_FP_SIZE && metadatafp != fingerprint) {
	LOGINFO("OTA_ERROR: %s\n", fingerprint.c_str());
    LOGINFO("OTA_ERROR: %s\n", metadatafp.c_str());
    return false;
	}
	return true;
	}
	
bool TWFunc::Verify_Loaded_OTA_Signature(std::string loadedfp, std::string ota_folder) {
	    std::string datafp;
        string ota_info = ota_folder + "/pb.info";
		if (TWFunc::Path_Exists(ota_info)) {
		if (TWFunc::read_file(ota_info, datafp) == 0) {
	    if (!datafp.empty() && datafp.size() > PB_MIN_EXPECTED_FP_SIZE && !loadedfp.empty() && loadedfp.size() > PB_MIN_EXPECTED_FP_SIZE && datafp == loadedfp) {
	    return true;
	    }
	   }
	}
	 return false;
	}

bool TWFunc::isNumber(string strtocheck) {
	int num = 0;
	std::istringstream iss(strtocheck);

	if (!(iss >> num).fail())
		return true;
	else
		return false;
}

int TWFunc::stream_adb_backup(string &Restore_Name) {
	string cmd = "/sbin/bu --twrp stream " + Restore_Name;
	LOGINFO("stream_adb_backup: %s\n", cmd.c_str());
	int ret = TWFunc::Exec_Cmd(cmd);
	if (ret != 0)
		return -1;
	return ret;
}

std::string TWFunc::get_log_dir() {
	if (PartitionManager.Find_Partition_By_Path(CACHE_LOGS_DIR) == NULL) {
		if (PartitionManager.Find_Partition_By_Path(DATA_LOGS_DIR) == NULL) {
			LOGINFO("Unable to find a directory to store TWRP logs.");
			return "";
		} else {
			return DATA_LOGS_DIR;
		}
	}
	else {
		return CACHE_LOGS_DIR;
	}
}

void TWFunc::check_selinux_support() {
	if (TWFunc::Path_Exists("/prebuilt_file_contexts")) {
		if (TWFunc::Path_Exists("/file_contexts")) {
			printf("Renaming regular /file_contexts -> /file_contexts.bak\n");
			rename("/file_contexts", "/file_contexts.bak");
		}
		printf("Moving /prebuilt_file_contexts -> /file_contexts\n");
		rename("/prebuilt_file_contexts", "/file_contexts");
	}
	struct selinux_opt selinux_options[] = {
		{ SELABEL_OPT_PATH, "/file_contexts" }
	};
	selinux_handle = selabel_open(SELABEL_CTX_FILE, selinux_options, 1);
	if (!selinux_handle)
		printf("No file contexts for SELinux\n");
	else
		printf("SELinux contexts loaded from /file_contexts\n");
	{ // Check to ensure SELinux can be supported by the kernel
		char *contexts = NULL;
		std::string cacheDir = TWFunc::get_log_dir();
		std::string se_context_check = cacheDir + "recovery/";
		int ret = 0;

		if (cacheDir == CACHE_LOGS_DIR) {
			PartitionManager.Mount_By_Path(CACHE_LOGS_DIR, false);
		}
		if (TWFunc::Path_Exists(se_context_check)) {
			ret = lgetfilecon(se_context_check.c_str(), &contexts);
			if (ret < 0) {
				LOGINFO("Could not check %s SELinux contexts, using /sbin/teamwin instead which may be inaccurate.\n", se_context_check.c_str());
				lgetfilecon("/sbin/teamwin", &contexts);
			}
		}
		if (ret < 0) {
			gui_warn("no_kernel_selinux=Kernel does not have support for reading SELinux contexts.");
		} else {
			free(contexts);
			gui_msg("full_selinux=Full SELinux support is present.");
		}
	}
}

int TWFunc::Property_Override(string Prop_Name, string Prop_Value) {
#ifdef TW_INCLUDE_LIBRESETPROP
    return setprop(Prop_Name.c_str(), Prop_Value.c_str(), false);
#else
    return Exec_Cmd("resetprop " + Prop_Name + " \"" + Prop_Value + "\"");
#endif
}

void TWFunc::List_Mounts() {
	std::vector<std::string> mounts;
	read_file("/proc/mounts", mounts);
	LOGINFO("Mounts:\n");
	for (auto&& mount: mounts) {
		LOGINFO("%s\n", mount.c_str());
	}
}

bool TWFunc::Get_Encryption_Policy(fscrypt_encryption_policy &policy, std::string path) {
	if (!TWFunc::Path_Exists(path)) {
		LOGERR("Unable to find %s to get policy\n", path.c_str());
		return false;
	}
	if (!fscrypt_policy_get_struct(path.c_str(), &policy)) {
		LOGERR("No policy set for path %s\n", path.c_str());
		return false;
	}
	return true;
}

bool TWFunc::Set_Encryption_Policy(std::string path, const fscrypt_encryption_policy &policy) {
	if (!TWFunc::Path_Exists(path)) {
		LOGERR("unable to find %s to set policy\n", path.c_str());
		return false;
	}
	uint8_t binary_policy[FS_KEY_DESCRIPTOR_SIZE];
	char policy_hex[FS_KEY_DESCRIPTOR_SIZE_HEX];
	policy_to_hex(binary_policy, policy_hex);
	if (!fscrypt_policy_set_struct(path.c_str(), &policy)) {
		LOGERR("unable to set policy for path: %s\n", path.c_str());
		return false;
	}
	return true;
}

std::string TWFunc::getprop(std::string arg)
{
	string value;
	TWFunc::Exec_Cmd("getprop " + arg, value);
	value.erase(std::remove(value.begin(), value.end(), '\n'), value.end());
	return value;
}

#endif // ndef BUILD_TWRPTAR_MAIN
