import os
import re
from setuptools import setup, find_packages, Extension
from setuptools.command.install import install
import subprocess

def get_kver(version, index):
    # Split the version string by dots and get the index-th word
    # If the index is out of range, return 0
    words = version.split(".")
    try:
        return words[index]
    except IndexError:
        return 0

def get_kvercode(major, minor, patch):
    # Check if the major, minor and patch are valid integers between 0 and 255
    # If yes, return the kvercode as a single integer
    # If no, return None
    try:
        major = int(major)
        minor = int(minor)
        patch = int(patch)
        if 0 <= major <= 255 and 0 <= minor <= 255 and 0 <= patch <= 255:
            return (major << 16) + (minor << 8) + patch
        else:
            return None
    except ValueError:
        return None



# Get the build kernel from the environment variable or use the current kernel
BUILD_KERNEL = os.environ.get("BUILD_KERNEL") or os.uname().release

# Define a list of possible kernel source paths
KSP = ["/lib/modules/%s/source" % BUILD_KERNEL,
       "/lib/modules/%s/build" % BUILD_KERNEL,
       "/usr/src/linux-%s" % BUILD_KERNEL,
       "/usr/src/linux-{re.sub('-.*', '', BUILD_KERNEL)}",
       "/usr/src/kernel-headers-%s" % BUILD_KERNEL,
       "/usr/src/kernel-source-%s" % BUILD_KERNEL,
       "/usr/src/linux-{re.sub('\\.[0-9]*\\..*', '', BUILD_KERNEL)}",
       "/usr/src/linux",
       "/usr/src/kernels/%s" % BUILD_KERNEL,
       "/usr/src/kernels"]

# Test if each path contains the include/linux directory and keep the valid ones
KSP = [dirc for dirc in KSP if os.path.exists(dirc + "/include/linux")]

# Use the first valid path as the kernel source or raise an error if none is found
if KSP:
    KSRC = KSP[0]
else:
    print("*** Kernel header files not in any of the expected locations.")
    print("*** Install the appropriate kernel development package, e.g. kernel-devel, for building kernel modules and try again")
    raise SystemExit

# Use the build path if the source path is /lib/modules/${BUILD_KERNEL}/source or use the source path otherwise
if KSRC == "/lib/modules/%s/source" % BUILD_KERNEL:
    KOBJ = "/lib/modules/%s/build" % BUILD_KERNEL
else:
    KOBJ = KSRC

# Get the script path from the kernel source
SCRIPT_PATH = "%s/scripts" % KSRC

# Define a list of possible version file paths
VSP = ["%s/include/generated/utsrelease.h" % KOBJ,
       "%s/include/linux/utsrelease.h" % KOBJ,
       "%s/include/linux/version.h" % KOBJ,
       "%s/include/generated/uapi/linux/version.h" % KOBJ,
       "/boot/vmlinuz.version.h"]

# Define a list of possible config file paths
CSP = ["%s/include/generated/autoconf.h" % KOBJ,
       "%s/include/linux/autoconf.h" % KOBJ,
       "/boot/vmlinuz.autoconf.h"]

# Define a list of possible system map file paths
MSP = ["%s/System.map" % KSRC,
       "/usr/lib/debug/boot/System.map-%s" % BUILD_KERNEL,
       "/boot/System.map-%s" % BUILD_KERNEL]

# Filter the lists to keep only the files that exist
VSP = [file for file in VSP if os.path.isfile(file)]
CSP = [file for file in CSP if os.path.isfile(file)]
MSP = [file for file in MSP if os.path.isfile(file)]

# Use the first valid file as the version file or raise an error if none is found
if VSP:
    VERSION_FILE = VSP[0]
else:
    raise SystemExit("Linux kernel source not configured - missing version header file")

# Use the first valid file as the config file or raise an error if none is found
if CSP:
    CONFIG_FILE = CSP[0]
else:
    raise SystemExit("Linux kernel source not configured - missing autoconf.h")

# Use the first valid file as the system map file or print a warning if none is found
if MSP:
    SYSTEM_MAP_FILE = MSP[0]
else:
    print("Missing System.map file - depmod will not check for missing symbols during module installation")


class CustomInstall(install):
    def run(self):
        process = subprocess.Popen(["make", "-C", "pktperf/module", "install"], shell=False)
        process.wait()
        super().run()

setup(
    has_ext_modules=lambda: True,
    cmdclass = {'install': CustomInstall}
)
