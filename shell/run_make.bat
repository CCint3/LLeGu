
SET NDKROOT=D:\Tools\Dev\android-ndk-r10e

SET PATH=%NDKROOT%\prebuilt\windows-x86_64\bin;%NDKROOT%\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\arm-linux-androideabi\bin;%PATH%

make ndk_root=%NDKROOT% compile

make ndk_root=%NDKROOT% link

strip -s -R .gnu* -R .comment -R .note* -R .ARM* shell.so

del shell.o
pause