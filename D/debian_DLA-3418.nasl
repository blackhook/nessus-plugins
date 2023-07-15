#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3418. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(175576);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id(
    "CVE-2022-34670",
    "CVE-2022-34674",
    "CVE-2022-34675",
    "CVE-2022-34677",
    "CVE-2022-34680",
    "CVE-2022-42257",
    "CVE-2022-42258",
    "CVE-2022-42259"
  );

  script_name(english:"Debian DLA-3418-1 : nvidia-graphics-drivers-legacy-390xx - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3418 advisory.

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where an
    unprivileged regular user can cause truncation errors when casting a primitive to a primitive of smaller
    size causes data to be lost in the conversion, which may lead to denial of service or information
    disclosure. (CVE-2022-34670)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where a
    helper function maps more physical pages than were requested, which may lead to undefined behavior or an
    information leak. (CVE-2022-34674)

  - NVIDIA Display Driver for Linux contains a vulnerability in the Virtual GPU Manager, where it does not
    check the return value from a null-pointer dereference, which may lead to denial of service.
    (CVE-2022-34675)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where an
    unprivileged regular user can cause an integer to be truncated, which may lead to denial of service or
    data tampering. (CVE-2022-34677)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where an
    integer truncation can lead to an out-of-bounds read, which may lead to denial of service.
    (CVE-2022-34680)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where
    an integer overflow may lead to information disclosure, data tampering or denial of service.
    (CVE-2022-42257)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where
    an integer overflow may lead to denial of service, data tampering, or information disclosure.
    (CVE-2022-42258)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where
    an integer overflow may lead to denial of service. (CVE-2022-42259)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1025281");
  # https://security-tracker.debian.org/tracker/source-package/nvidia-graphics-drivers-legacy-390xx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?861b6afb");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3418");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-34670");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-34674");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-34675");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-34677");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-34680");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42257");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42258");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42259");
  # https://packages.debian.org/source/buster/nvidia-graphics-drivers-legacy-390xx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b085f5e4");
  script_set_attribute(attribute:"solution", value:
"Upgrade the nvidia-graphics-drivers-legacy-390xx packages.

For Debian 10 buster, these problems have been fixed in version 390.157-1~deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34670");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libegl-nvidia-legacy-390xx0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libegl1-nvidia-legacy-390xx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgl1-nvidia-legacy-390xx-glvnd-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgl1-nvidia-legacy-390xx-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgles-nvidia-legacy-390xx1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgles-nvidia-legacy-390xx2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libglx-nvidia-legacy-390xx0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-legacy-390xx-cfg1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-legacy-390xx-compiler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-legacy-390xx-cuda1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-legacy-390xx-cuda1-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-legacy-390xx-eglcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-legacy-390xx-encode1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-legacy-390xx-fatbinaryloader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-legacy-390xx-fbc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-legacy-390xx-glcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-legacy-390xx-ifr1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-legacy-390xx-ml1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-legacy-390xx-nvcuvid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvidia-legacy-390xx-ptxjitcompiler1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-legacy-390xx-alternative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-legacy-390xx-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-legacy-390xx-driver-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-legacy-390xx-driver-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-legacy-390xx-driver-libs-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-legacy-390xx-driver-libs-nonglvnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-legacy-390xx-driver-libs-nonglvnd-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-legacy-390xx-egl-icd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-legacy-390xx-kernel-dkms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-legacy-390xx-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-legacy-390xx-kernel-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-legacy-390xx-nonglvnd-vulkan-icd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-legacy-390xx-opencl-icd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-legacy-390xx-smi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-legacy-390xx-vdpau-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvidia-legacy-390xx-vulkan-icd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xorg-video-nvidia-legacy-390xx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libegl-nvidia-legacy-390xx0', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'libegl1-nvidia-legacy-390xx', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'libgl1-nvidia-legacy-390xx-glvnd-glx', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'libgl1-nvidia-legacy-390xx-glx', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'libgles-nvidia-legacy-390xx1', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'libgles-nvidia-legacy-390xx2', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'libglx-nvidia-legacy-390xx0', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'libnvidia-legacy-390xx-cfg1', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'libnvidia-legacy-390xx-compiler', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'libnvidia-legacy-390xx-cuda1', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'libnvidia-legacy-390xx-cuda1-i386', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'libnvidia-legacy-390xx-eglcore', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'libnvidia-legacy-390xx-encode1', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'libnvidia-legacy-390xx-fatbinaryloader', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'libnvidia-legacy-390xx-fbc1', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'libnvidia-legacy-390xx-glcore', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'libnvidia-legacy-390xx-ifr1', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'libnvidia-legacy-390xx-ml1', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'libnvidia-legacy-390xx-nvcuvid1', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'libnvidia-legacy-390xx-ptxjitcompiler1', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'nvidia-legacy-390xx-alternative', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'nvidia-legacy-390xx-driver', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'nvidia-legacy-390xx-driver-bin', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'nvidia-legacy-390xx-driver-libs', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'nvidia-legacy-390xx-driver-libs-i386', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'nvidia-legacy-390xx-driver-libs-nonglvnd', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'nvidia-legacy-390xx-driver-libs-nonglvnd-i386', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'nvidia-legacy-390xx-egl-icd', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'nvidia-legacy-390xx-kernel-dkms', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'nvidia-legacy-390xx-kernel-source', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'nvidia-legacy-390xx-kernel-support', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'nvidia-legacy-390xx-nonglvnd-vulkan-icd', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'nvidia-legacy-390xx-opencl-icd', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'nvidia-legacy-390xx-smi', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'nvidia-legacy-390xx-vdpau-driver', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'nvidia-legacy-390xx-vulkan-icd', 'reference': '390.157-1~deb10u1'},
    {'release': '10.0', 'prefix': 'xserver-xorg-video-nvidia-legacy-390xx', 'reference': '390.157-1~deb10u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libegl-nvidia-legacy-390xx0 / libegl1-nvidia-legacy-390xx / etc');
}
