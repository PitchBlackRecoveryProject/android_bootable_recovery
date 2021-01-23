local_c_flags := -DUSE_OPENSSL_PBKDF2

local_c_includes := $(log_c_includes) external/openssl/include external/boringssl/src/include

local_additional_dependencies := $(LOCAL_PATH)/android-config.mk $(LOCAL_PATH)/Scrypt.mk

include $(LOCAL_PATH)/Scrypt-config.mk
