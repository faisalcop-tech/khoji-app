[app]
title = Khoji Pro
package.name = khojipro
package.domain = org.faisalmalik
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,dat,csv
version = 4.0
requirements = python3,kivy==2.3.0
orientation = portrait
fullscreen = 0
android.permissions = ACCESS_FINE_LOCATION,ACCESS_COARSE_LOCATION,READ_PHONE_STATE,INTERNET,ACCESS_NETWORK_STATE,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE
android.api = 33
android.minapi = 21
android.ndk = 25b
android.archs = arm64-v8a
android.accept_sdk_license = True
android.sdk_path = /home/runner/android-sdk
android.ndk_path = /home/runner/android-sdk/ndk/25.2.9519653

[buildozer]
log_level = 2
warn_on_root = 1
