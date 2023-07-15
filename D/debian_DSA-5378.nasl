#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5378. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(173415);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/28");

  script_cve_id(
    "CVE-2022-23824",
    "CVE-2022-42331",
    "CVE-2022-42332",
    "CVE-2022-42333",
    "CVE-2022-42334"
  );

  script_name(english:"Debian DSA-5378-1 : xen - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5378 advisory.

  - IBPB may not prevent return branch predictions from being specified by pre-IBPB branch targets leading to
    a potential information disclosure. (CVE-2022-23824)

  - x86: speculative vulnerability in 32bit SYSCALL path Due to an oversight in the very original
    Spectre/Meltdown security work (XSA-254), one entrypath performs its speculation-safety actions too late.
    In some configurations, there is an unprotected RET instruction which can be attacked with a variety of
    speculative attacks. (CVE-2022-42331)

  - x86 shadow plus log-dirty mode use-after-free In environments where host assisted address translation is
    necessary but Hardware Assisted Paging (HAP) is unavailable, Xen will run guests in so called shadow mode.
    Shadow mode maintains a pool of memory used for both shadow page tables as well as auxiliary data
    structures. To migrate or snapshot guests, Xen additionally runs them in so called log-dirty mode. The
    data structures needed by the log-dirty tracking are part of aformentioned auxiliary data. In order to
    keep error handling efforts within reasonable bounds, for operations which may require memory allocations
    shadow mode logic ensures up front that enough memory is available for the worst case requirements.
    Unfortunately, while page table memory is properly accounted for on the code path requiring the potential
    establishing of new shadows, demands by the log-dirty infrastructure were not taken into consideration. As
    a result, just established shadow page tables could be freed again immediately, while other code is still
    accessing them on the assumption that they would remain allocated. (CVE-2022-42332)

  - x86/HVM pinned cache attributes mis-handling T[his CNA information record relates to multiple CVEs; the
    text explains which aspects/vulnerabilities correspond to which CVE.] To allow cachability control for HVM
    guests with passed through devices, an interface exists to explicitly override defaults which would
    otherwise be put in place. While not exposed to the affected guests themselves, the interface specifically
    exists for domains controlling such guests. This interface may therefore be used by not fully privileged
    entities, e.g. qemu running deprivileged in Dom0 or qemu running in a so called stub-domain. With this
    exposure it is an issue that - the number of the such controlled regions was unbounded (CVE-2022-42333), -
    installation and removal of such regions was not properly serialized (CVE-2022-42334). (CVE-2022-42333,
    CVE-2022-42334)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1033297");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/xen");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5378");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23824");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42331");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42332");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42333");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42334");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/xen");
  script_set_attribute(attribute:"solution", value:
"Upgrade the xen packages.

For the stable distribution (bullseye), these problems have been fixed in version 4.14.5+94-ge49571868d-1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42332");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxen-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxencall1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxendevicemodel1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxenevtchn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxenforeignmemory1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxengnttab1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxenhypfs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxenmisc4.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxenstore3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxentoolcore1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxentoollog1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-hypervisor-4.14-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-hypervisor-4.14-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-hypervisor-4.14-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-hypervisor-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-system-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-system-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-system-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-utils-4.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-utils-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xenstore-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'libxen-dev', 'reference': '4.14.5+94-ge49571868d-1'},
    {'release': '11.0', 'prefix': 'libxencall1', 'reference': '4.14.5+94-ge49571868d-1'},
    {'release': '11.0', 'prefix': 'libxendevicemodel1', 'reference': '4.14.5+94-ge49571868d-1'},
    {'release': '11.0', 'prefix': 'libxenevtchn1', 'reference': '4.14.5+94-ge49571868d-1'},
    {'release': '11.0', 'prefix': 'libxenforeignmemory1', 'reference': '4.14.5+94-ge49571868d-1'},
    {'release': '11.0', 'prefix': 'libxengnttab1', 'reference': '4.14.5+94-ge49571868d-1'},
    {'release': '11.0', 'prefix': 'libxenhypfs1', 'reference': '4.14.5+94-ge49571868d-1'},
    {'release': '11.0', 'prefix': 'libxenmisc4.14', 'reference': '4.14.5+94-ge49571868d-1'},
    {'release': '11.0', 'prefix': 'libxenstore3.0', 'reference': '4.14.5+94-ge49571868d-1'},
    {'release': '11.0', 'prefix': 'libxentoolcore1', 'reference': '4.14.5+94-ge49571868d-1'},
    {'release': '11.0', 'prefix': 'libxentoollog1', 'reference': '4.14.5+94-ge49571868d-1'},
    {'release': '11.0', 'prefix': 'xen-doc', 'reference': '4.14.5+94-ge49571868d-1'},
    {'release': '11.0', 'prefix': 'xen-hypervisor-4.14-amd64', 'reference': '4.14.5+94-ge49571868d-1'},
    {'release': '11.0', 'prefix': 'xen-hypervisor-4.14-arm64', 'reference': '4.14.5+94-ge49571868d-1'},
    {'release': '11.0', 'prefix': 'xen-hypervisor-4.14-armhf', 'reference': '4.14.5+94-ge49571868d-1'},
    {'release': '11.0', 'prefix': 'xen-hypervisor-common', 'reference': '4.14.5+94-ge49571868d-1'},
    {'release': '11.0', 'prefix': 'xen-system-amd64', 'reference': '4.14.5+94-ge49571868d-1'},
    {'release': '11.0', 'prefix': 'xen-system-arm64', 'reference': '4.14.5+94-ge49571868d-1'},
    {'release': '11.0', 'prefix': 'xen-system-armhf', 'reference': '4.14.5+94-ge49571868d-1'},
    {'release': '11.0', 'prefix': 'xen-utils-4.14', 'reference': '4.14.5+94-ge49571868d-1'},
    {'release': '11.0', 'prefix': 'xen-utils-common', 'reference': '4.14.5+94-ge49571868d-1'},
    {'release': '11.0', 'prefix': 'xenstore-utils', 'reference': '4.14.5+94-ge49571868d-1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libxen-dev / libxencall1 / libxendevicemodel1 / libxenevtchn1 / etc');
}
