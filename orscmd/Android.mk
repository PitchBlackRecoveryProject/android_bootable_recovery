LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

ifeq ($(PB_OFFICIAL),true)
	ifeq ($(PB_GO),true)
	    LOCAL_CFLAGS += -DTW_DEVICE_VERSION='"-PB-GO-v2.9.1-Official"'
	else
	    LOCAL_CFLAGS += -DTW_DEVICE_VERSION='"-PB-v2.9.1-Official"'
	endif
else
        ifeq ($(PB_GO),true)
            LOCAL_CFLAGS += -DTW_DEVICE_VERSION='"-PB-GO-v2.9.1-Unofficial"'
	else
	    LOCAL_CFLAGS += -DTW_DEVICE_VERSION='"-PB-v2.9.1-Unofficial"'
	endif
endif

LOCAL_SRC_FILES:= \
	orscmd.cpp
LOCAL_CFLAGS += -c -W
LOCAL_MODULE := orscmd
LOCAL_MODULE_STEM := twrp
LOCAL_MODULE_TAGS:= optional
LOCAL_MODULE_CLASS := RECOVERY_EXECUTABLES
LOCAL_PACK_MODULE_RELOCATIONS := false
LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/sbin
include $(BUILD_EXECUTABLE)
