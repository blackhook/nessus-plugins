#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2713. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151891);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_cve_id(
    "CVE-2021-3609",
    "CVE-2021-21781",
    "CVE-2021-33909",
    "CVE-2021-34693"
  );
  script_xref(name:"IAVA", value:"2021-A-0350");

  script_name(english:"Debian DLA-2713-1 : linux - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2713 advisory.

  - fs/seq_file.c in the Linux kernel 3.16 through 5.13.x before 5.13.4 does not properly restrict seq buffer
    allocations, leading to an integer overflow, an Out-of-bounds Write, and escalation to root by an
    unprivileged user, aka CID-8cae8cd89f05. (CVE-2021-33909)

  - net/can/bcm.c in the Linux kernel through 5.12.10 allows local users to obtain sensitive information from
    kernel stack memory because parts of a data structure are uninitialized. (CVE-2021-34693)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=990072");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2713");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21781");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33909");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-34693");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3609");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux packages.

For Debian 9 stretch, these problems have been fixed in version 4.9.272-2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33909");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyperv-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libusbip-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-6-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-6-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-14-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-14-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-14-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-14-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-14-all-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-14-all-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-14-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-14-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-14-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-14-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-14-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-14-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-14-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-14-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-14-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-14-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-14-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-14-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-14-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-14-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-14-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-14-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-14-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-14-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-14-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-14-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-14-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-14-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-14-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-14-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-14-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-14-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-14-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-14-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-14-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-manual-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-4.9.0-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usbip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

pkgs = [
    {'release': '9.0', 'prefix': 'hyperv-daemons', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'libcpupower-dev', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'libcpupower1', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'libusbip-dev', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-compiler-gcc-6-arm', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-compiler-gcc-6-x86', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-cpupower', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-doc-4.9', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-14-686', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-14-686-pae', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-14-all', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-14-all-amd64', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-14-all-arm64', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-14-all-armel', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-14-all-armhf', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-14-all-i386', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-14-amd64', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-14-arm64', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-14-armmp', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-14-armmp-lpae', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-14-common', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-14-common-rt', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-14-marvell', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-14-rt-686-pae', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-headers-4.9.0-14-rt-amd64', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-14-686', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-14-686-dbg', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-14-686-pae', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-14-686-pae-dbg', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-14-amd64', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-14-amd64-dbg', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-14-arm64', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-14-arm64-dbg', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-14-armmp', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-14-armmp-dbg', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-14-armmp-lpae', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-14-armmp-lpae-dbg', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-14-marvell', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-14-marvell-dbg', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-14-rt-686-pae', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-14-rt-686-pae-dbg', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-14-rt-amd64', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-image-4.9.0-14-rt-amd64-dbg', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-kbuild-4.9', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-libc-dev', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-manual-4.9', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-perf-4.9', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-source-4.9', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'linux-support-4.9.0-14', 'reference': '4.9.272-2'},
    {'release': '9.0', 'prefix': 'usbip', 'reference': '4.9.272-2'}
];

flag = 0;
foreach package_array ( pkgs ) {
  release = NULL;
  prefix = NULL;
  reference = NULL;
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hyperv-daemons / libcpupower-dev / libcpupower1 / libusbip-dev / etc');
}
