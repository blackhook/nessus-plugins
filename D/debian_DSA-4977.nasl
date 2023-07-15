#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-4977. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153509);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-28694",
    "CVE-2021-28695",
    "CVE-2021-28696",
    "CVE-2021-28697",
    "CVE-2021-28698",
    "CVE-2021-28699",
    "CVE-2021-28700",
    "CVE-2021-28701"
  );
  script_xref(name:"IAVB", value:"2021-B-0060-S");

  script_name(english:"Debian DSA-4977-1 : xen - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-4977 advisory.

  - IOMMU page mapping issues on x86 T[his CNA information record relates to multiple CVEs; the text explains
    which aspects/vulnerabilities correspond to which CVE.] Both AMD and Intel allow ACPI tables to specify
    regions of memory which should be left untranslated, which typically means these addresses should pass the
    translation phase unaltered. While these are typically device specific ACPI properties, they can also be
    specified to apply to a range of devices, or even all devices. On all systems with such regions Xen failed
    to prevent guests from undoing/replacing such mappings (CVE-2021-28694). On AMD systems, where a
    discontinuous range is specified by firmware, the supposedly-excluded middle range will also be identity-
    mapped (CVE-2021-28695). Further, on AMD systems, upon de-assigment of a physical device from a guest, the
    identity mappings would be left in place, allowing a guest continued access to ranges of memory which it
    shouldn't have access to anymore (CVE-2021-28696). (CVE-2021-28694, CVE-2021-28695, CVE-2021-28696)

  - grant table v2 status pages may remain accessible after de-allocation Guest get permitted access to
    certain Xen-owned pages of memory. The majority of such pages remain allocated / associated with a guest
    for its entire lifetime. Grant table v2 status pages, however, get de-allocated when a guest switched
    (back) from v2 to v1. The freeing of such pages requires that the hypervisor know where in the guest these
    pages were mapped. The hypervisor tracks only one use within guest space, but racing requests from the
    guest to insert mappings of these pages may result in any of them to become mapped in multiple locations.
    Upon switching back from v2 to v1, the guest would then retain access to a page that was freed and perhaps
    re-used for other purposes. (CVE-2021-28697)

  - long running loops in grant table handling In order to properly monitor resource use, Xen maintains
    information on the grant mappings a domain may create to map grants offered by other domains. In the
    process of carrying out certain actions, Xen would iterate over all such entries, including ones which
    aren't in use anymore and some which may have been created but never used. If the number of entries for a
    given domain is large enough, this iterating of the entire table may tie up a CPU for too long, starving
    other domains or causing issues in the hypervisor itself. Note that a domain may map its own grants, i.e.
    there is no need for multiple domains to be involved here. A pair of cooperating guests may, however,
    cause the effects to be more severe. (CVE-2021-28698)

  - inadequate grant-v2 status frames array bounds check The v2 grant table interface separates grant
    attributes from grant status. That is, when operating in this mode, a guest has two tables. As a result,
    guests also need to be able to retrieve the addresses that the new status tracking table can be accessed
    through. For 32-bit guests on x86, translation of requests has to occur because the interface structure
    layouts commonly differ between 32- and 64-bit. The translation of the request to obtain the frame numbers
    of the grant status table involves translating the resulting array of frame numbers. Since the space used
    to carry out the translation is limited, the translation layer tells the core function the capacity of the
    array within translation space. Unfortunately the core function then only enforces array bounds to be
    below 8 times the specified value, and would write past the available space if enough frame numbers needed
    storing. (CVE-2021-28699)

  - xen/arm: No memory limit for dom0less domUs The dom0less feature allows an administrator to create
    multiple unprivileged domains directly from Xen. Unfortunately, the memory limit from them is not set.
    This allow a domain to allocate memory beyond what an administrator originally configured.
    (CVE-2021-28700)

  - Another race in XENMAPSPACE_grant_table handling Guests are permitted access to certain Xen-owned pages of
    memory. The majority of such pages remain allocated / associated with a guest for its entire lifetime.
    Grant table v2 status pages, however, are de-allocated when a guest switches (back) from v2 to v1. Freeing
    such pages requires that the hypervisor enforce that no parallel request can result in the addition of a
    mapping of such a page to a guest. That enforcement was missing, allowing guests to retain access to pages
    that were freed and perhaps re-used for other purposes. Unfortunately, when XSA-379 was being prepared,
    this similar issue was not noticed. (CVE-2021-28701)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/xen");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-4977");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28694");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28695");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28696");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28697");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28698");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28699");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28700");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28701");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/xen");
  script_set_attribute(attribute:"solution", value:
"Upgrade the xen packages.

For the stable distribution (bullseye), these problems have been fixed in version 4.14.3-1~deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28697");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-28701");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/21");

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
  script_set_attribute(attribute:"stig_severity", value:"I");
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

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'libxen-dev', 'reference': '4.14.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libxencall1', 'reference': '4.14.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libxendevicemodel1', 'reference': '4.14.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libxenevtchn1', 'reference': '4.14.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libxenforeignmemory1', 'reference': '4.14.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libxengnttab1', 'reference': '4.14.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libxenhypfs1', 'reference': '4.14.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libxenmisc4.14', 'reference': '4.14.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libxenstore3.0', 'reference': '4.14.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libxentoolcore1', 'reference': '4.14.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libxentoollog1', 'reference': '4.14.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xen-doc', 'reference': '4.14.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xen-hypervisor-4.14-amd64', 'reference': '4.14.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xen-hypervisor-4.14-arm64', 'reference': '4.14.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xen-hypervisor-4.14-armhf', 'reference': '4.14.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xen-hypervisor-common', 'reference': '4.14.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xen-system-amd64', 'reference': '4.14.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xen-system-arm64', 'reference': '4.14.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xen-system-armhf', 'reference': '4.14.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xen-utils-4.14', 'reference': '4.14.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xen-utils-common', 'reference': '4.14.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xenstore-utils', 'reference': '4.14.3-1~deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libxen-dev / libxencall1 / libxendevicemodel1 / libxenevtchn1 / etc');
}
