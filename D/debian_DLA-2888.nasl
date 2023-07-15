#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2888. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156794);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/18");

  script_cve_id(
    "CVE-2021-1056",
    "CVE-2021-1076",
    "CVE-2021-1093",
    "CVE-2021-1094",
    "CVE-2021-1095"
  );

  script_name(english:"Debian DLA-2888-1 : nvidia-graphics-drivers - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2888 advisory.

  - NVIDIA GPU Display Driver for Linux, all versions, contains a vulnerability in the kernel mode layer
    (nvidia.ko) in which it does not completely honor operating system file system permissions to provide GPU
    device-level isolation, which may lead to denial of service or information disclosure. (CVE-2021-1056)

  - NVIDIA GPU Display Driver for Windows and Linux, all versions, contains a vulnerability in the kernel mode
    layer (nvlddmkm.sys or nvidia.ko) where improper access control may lead to denial of service, information
    disclosure, or data corruption. (CVE-2021-1076)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in firmware where the driver
    contains an assert() or similar statement that can be triggered by an attacker, which leads to an
    application exit or other behavior that is more severe than necessary, and may lead to denial of service
    or system crash. (CVE-2021-1093)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer
    (nvlddmkm.sys) handler for DxgkDdiEscape where an out of bounds array access may lead to denial of service
    or information disclosure. (CVE-2021-1094)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer
    (nvlddmkm.sys) handlers for all control calls with embedded parameters where dereferencing an untrusted
    pointer may lead to denial of service. (CVE-2021-1095)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=987216");
  # https://security-tracker.debian.org/tracker/source-package/nvidia-graphics-drivers
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8601151");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2888");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-1056");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-1076");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-1093");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-1094");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-1095");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/nvidia-graphics-drivers");
  script_set_attribute(attribute:"solution", value:
"Upgrade the nvidia-graphics-drivers packages.

For Debian 9 stretch, these problems have been fixed in version 390.144-1~deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1076");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcuda1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcuda1-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libegl-nvidia0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libegl1-glvnd-nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libegl1-nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgl1-glvnd-nvidia-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgl1-nvidia-glvnd-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgl1-nvidia-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgles-nvidia1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgles-nvidia2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgles1-glvnd-nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgles1-nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgles2-glvnd-nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgles2-nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libglvnd0-nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libglx-nvidia0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libglx0-glvnd-nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvcuvid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-cfg1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-compiler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-eglcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-encode1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-fatbinaryloader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-fbc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-glcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-ifr1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-ml1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-ptxjitcompiler1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopengl0-glvnd-nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-alternative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-cuda-mps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-detect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-driver-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-driver-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-driver-libs-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-driver-libs-nonglvnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-driver-libs-nonglvnd-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-egl-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-egl-icd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-kernel-dkms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-kernel-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-legacy-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-libopencl1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-nonglvnd-vulkan-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-nonglvnd-vulkan-icd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-opencl-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-opencl-icd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-smi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-vdpau-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-vulkan-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-vulkan-icd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xorg-video-nvidia");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'libcuda1', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libcuda1-i386', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libegl-nvidia0', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libegl1-glvnd-nvidia', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libegl1-nvidia', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libgl1-glvnd-nvidia-glx', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libgl1-nvidia-glvnd-glx', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libgl1-nvidia-glx', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libgles-nvidia1', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libgles-nvidia2', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libgles1-glvnd-nvidia', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libgles1-nvidia', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libgles2-glvnd-nvidia', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libgles2-nvidia', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libglvnd0-nvidia', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libglx-nvidia0', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libglx0-glvnd-nvidia', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libnvcuvid1', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libnvidia-cfg1', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libnvidia-compiler', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libnvidia-eglcore', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libnvidia-encode1', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libnvidia-fatbinaryloader', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libnvidia-fbc1', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libnvidia-glcore', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libnvidia-ifr1', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libnvidia-ml1', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libnvidia-ptxjitcompiler1', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'libopengl0-glvnd-nvidia', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-alternative', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-cuda-mps', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-detect', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-driver', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-driver-bin', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-driver-libs', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-driver-libs-i386', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-driver-libs-nonglvnd', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-driver-libs-nonglvnd-i386', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-egl-common', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-egl-icd', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-kernel-dkms', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-kernel-source', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-kernel-support', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-legacy-check', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-libopencl1', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-nonglvnd-vulkan-common', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-nonglvnd-vulkan-icd', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-opencl-common', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-opencl-icd', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-smi', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-vdpau-driver', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-vulkan-common', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'nvidia-vulkan-icd', 'reference': '390.144-1~deb9u1'},
    {'release': '9.0', 'prefix': 'xserver-xorg-video-nvidia', 'reference': '390.144-1~deb9u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcuda1 / libcuda1-i386 / libegl-nvidia0 / libegl1-glvnd-nvidia / etc');
}
