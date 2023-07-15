#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5017. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155870);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id(
    "CVE-2021-28702",
    "CVE-2021-28704",
    "CVE-2021-28705",
    "CVE-2021-28706",
    "CVE-2021-28707",
    "CVE-2021-28708",
    "CVE-2021-28709"
  );
  script_xref(name:"IAVB", value:"2021-B-0044-S");
  script_xref(name:"IAVB", value:"2021-B-0068-S");

  script_name(english:"Debian DSA-5017-1 : xen - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5017 advisory.

  - PCI devices with RMRRs not deassigned correctly Certain PCI devices in a system might be assigned Reserved
    Memory Regions (specified via Reserved Memory Region Reporting, RMRR). These are typically used for
    platform tasks such as legacy USB emulation. If such a device is passed through to a guest, then on guest
    shutdown the device is not properly deassigned. The IOMMU configuration for these devices which are not
    properly deassigned ends up pointing to a freed data structure, including the IO Pagetables. Subsequent
    DMA or interrupts from the device will have unpredictable behaviour, ranging from IOMMU faults to memory
    corruption. (CVE-2021-28702)

  - PoD operations on misaligned GFNs T[his CNA information record relates to multiple CVEs; the text explains
    which aspects/vulnerabilities correspond to which CVE.] x86 HVM and PVH guests may be started in populate-
    on-demand (PoD) mode, to provide a way for them to later easily have more memory assigned. Guests are
    permitted to control certain P2M aspects of individual pages via hypercalls. These hypercalls may act on
    ranges of pages specified via page orders (resulting in a power-of-2 number of pages). The implementation
    of some of these hypercalls for PoD does not enforce the base page frame number to be suitably aligned for
    the specified order, yet some code involved in PoD handling actually makes such an assumption. These
    operations are XENMEM_decrease_reservation (CVE-2021-28704) and XENMEM_populate_physmap (CVE-2021-28707),
    the latter usable only by domains controlling the guest, i.e. a de-privileged qemu or a stub domain.
    (Patch 1, combining the fix to both these two issues.) In addition handling of XENMEM_decrease_reservation
    can also trigger a host crash when the specified page order is neither 4k nor 2M nor 1G (CVE-2021-28708,
    patch 2). (CVE-2021-28704, CVE-2021-28707, CVE-2021-28708)

  - issues with partially successful P2M updates on x86 T[his CNA information record relates to multiple CVEs;
    the text explains which aspects/vulnerabilities correspond to which CVE.] x86 HVM and PVH guests may be
    started in populate-on-demand (PoD) mode, to provide a way for them to later easily have more memory
    assigned. Guests are permitted to control certain P2M aspects of individual pages via hypercalls. These
    hypercalls may act on ranges of pages specified via page orders (resulting in a power-of-2 number of
    pages). In some cases the hypervisor carries out the requests by splitting them into smaller chunks. Error
    handling in certain PoD cases has been insufficient in that in particular partial success of some
    operations was not properly accounted for. There are two code paths affected - page removal
    (CVE-2021-28705) and insertion of new pages (CVE-2021-28709). (We provide one patch which combines the fix
    to both issues.) (CVE-2021-28705, CVE-2021-28709)

  - guests may exceed their designated memory limit When a guest is permitted to have close to 16TiB of
    memory, it may be able to issue hypercalls to increase its memory allocation beyond the administrator
    established limit. This is a result of a calculation done with 32-bit precision, which may overflow. It
    would then only be the overflowed (and hence small) number which gets compared against the established
    upper bound. (CVE-2021-28706)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/xen");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-5017");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28702");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28704");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28705");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28706");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28707");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28708");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28709");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/xen");
  script_set_attribute(attribute:"solution", value:
"Upgrade the xen packages.

For the stable distribution (bullseye), these problems have been fixed in version 4.14.3+32-g9de3671772-1~deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28709");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-28708");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/06");

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
    {'release': '11.0', 'prefix': 'libxen-dev', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libxencall1', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libxendevicemodel1', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libxenevtchn1', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libxenforeignmemory1', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libxengnttab1', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libxenhypfs1', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libxenmisc4.14', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libxenstore3.0', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libxentoolcore1', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libxentoollog1', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xen-doc', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xen-hypervisor-4.14-amd64', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xen-hypervisor-4.14-arm64', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xen-hypervisor-4.14-armhf', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xen-hypervisor-common', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xen-system-amd64', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xen-system-arm64', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xen-system-armhf', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xen-utils-4.14', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xen-utils-common', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'},
    {'release': '11.0', 'prefix': 'xenstore-utils', 'reference': '4.14.3+32-g9de3671772-1~deb11u1'}
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
