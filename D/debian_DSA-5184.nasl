#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5184. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(163265);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2022-21123",
    "CVE-2022-21125",
    "CVE-2022-21166",
    "CVE-2022-23816",
    "CVE-2022-23825",
    "CVE-2022-26362",
    "CVE-2022-26363",
    "CVE-2022-26364",
    "CVE-2022-29900"
  );
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"Debian DSA-5184-1 : xen - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5184 advisory.

  - Incomplete cleanup of multi-core shared buffers for some Intel(R) Processors may allow an authenticated
    user to potentially enable information disclosure via local access. (CVE-2022-21123)

  - Incomplete cleanup of microarchitectural fill buffers on some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2022-21125)

  - Incomplete cleanup in specific special register write operations for some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2022-21166)

  - Aliases in the branch predictor may cause some AMD processors to predict the wrong branch type potentially
    leading to information disclosure. (CVE-2022-23825)

  - x86 pv: Race condition in typeref acquisition Xen maintains a type reference count for pages, in addition
    to a regular reference count. This scheme is used to maintain invariants required for Xen's safety, e.g.
    PV guests may not have direct writeable access to pagetables; updates need auditing by Xen. Unfortunately,
    the logic for acquiring a type reference has a race condition, whereby a safely TLB flush is issued too
    early and creates a window where the guest can re-establish the read/write mapping before writeability is
    prohibited. (CVE-2022-26362)

  - x86 pv: Insufficient care with non-coherent mappings T[his CNA information record relates to multiple
    CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Xen maintains a type
    reference count for pages, in addition to a regular reference count. This scheme is used to maintain
    invariants required for Xen's safety, e.g. PV guests may not have direct writeable access to pagetables;
    updates need auditing by Xen. Unfortunately, Xen's safety logic doesn't account for CPU-induced cache non-
    coherency; cases where the CPU can cause the content of the cache to be different to the content in main
    memory. In such cases, Xen's safety logic can incorrectly conclude that the contents of a page is safe.
    (CVE-2022-26363, CVE-2022-26364)

  - AMD microprocessor families 15h to 18h are affected by a new Spectre variant that is able to bypass their
    retpoline mitigation in the kernel to leak arbitrary data. An attacker with unprivileged user access can
    hijack return instructions to achieve arbitrary speculative code execution under certain
    microarchitecture-dependent conditions. (CVE-2022-29900)

  - AMD: CVE-2022-23816 AMD CPU Branch Type Confusion (CVE-2022-23816)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/xen");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5184");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21123");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21125");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21166");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23816");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23825");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26362");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26363");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26364");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-29900");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/xen");
  script_set_attribute(attribute:"solution", value:
"Upgrade the xen packages.

For the stable distribution (bullseye), these problems have been fixed in version 4.14.5+24-g87d90d511c-1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26364");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/16");

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
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'libxen-dev', 'reference': '4.14.5+24-g87d90d511c-1'},
    {'release': '11.0', 'prefix': 'libxencall1', 'reference': '4.14.5+24-g87d90d511c-1'},
    {'release': '11.0', 'prefix': 'libxendevicemodel1', 'reference': '4.14.5+24-g87d90d511c-1'},
    {'release': '11.0', 'prefix': 'libxenevtchn1', 'reference': '4.14.5+24-g87d90d511c-1'},
    {'release': '11.0', 'prefix': 'libxenforeignmemory1', 'reference': '4.14.5+24-g87d90d511c-1'},
    {'release': '11.0', 'prefix': 'libxengnttab1', 'reference': '4.14.5+24-g87d90d511c-1'},
    {'release': '11.0', 'prefix': 'libxenhypfs1', 'reference': '4.14.5+24-g87d90d511c-1'},
    {'release': '11.0', 'prefix': 'libxenmisc4.14', 'reference': '4.14.5+24-g87d90d511c-1'},
    {'release': '11.0', 'prefix': 'libxenstore3.0', 'reference': '4.14.5+24-g87d90d511c-1'},
    {'release': '11.0', 'prefix': 'libxentoolcore1', 'reference': '4.14.5+24-g87d90d511c-1'},
    {'release': '11.0', 'prefix': 'libxentoollog1', 'reference': '4.14.5+24-g87d90d511c-1'},
    {'release': '11.0', 'prefix': 'xen-doc', 'reference': '4.14.5+24-g87d90d511c-1'},
    {'release': '11.0', 'prefix': 'xen-hypervisor-4.14-amd64', 'reference': '4.14.5+24-g87d90d511c-1'},
    {'release': '11.0', 'prefix': 'xen-hypervisor-4.14-arm64', 'reference': '4.14.5+24-g87d90d511c-1'},
    {'release': '11.0', 'prefix': 'xen-hypervisor-4.14-armhf', 'reference': '4.14.5+24-g87d90d511c-1'},
    {'release': '11.0', 'prefix': 'xen-hypervisor-common', 'reference': '4.14.5+24-g87d90d511c-1'},
    {'release': '11.0', 'prefix': 'xen-system-amd64', 'reference': '4.14.5+24-g87d90d511c-1'},
    {'release': '11.0', 'prefix': 'xen-system-arm64', 'reference': '4.14.5+24-g87d90d511c-1'},
    {'release': '11.0', 'prefix': 'xen-system-armhf', 'reference': '4.14.5+24-g87d90d511c-1'},
    {'release': '11.0', 'prefix': 'xen-utils-4.14', 'reference': '4.14.5+24-g87d90d511c-1'},
    {'release': '11.0', 'prefix': 'xen-utils-common', 'reference': '4.14.5+24-g87d90d511c-1'},
    {'release': '11.0', 'prefix': 'xenstore-utils', 'reference': '4.14.5+24-g87d90d511c-1'}
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
    severity   : SECURITY_HOLE,
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
