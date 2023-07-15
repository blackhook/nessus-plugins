#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2970. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159511);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/09");

  script_cve_id(
    "CVE-2021-3593",
    "CVE-2021-3748",
    "CVE-2021-3930",
    "CVE-2021-20196",
    "CVE-2022-26354"
  );

  script_name(english:"Debian DLA-2970-1 : qemu - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2970 advisory.

  - A NULL pointer dereference flaw was found in the floppy disk emulator of QEMU. This issue occurs while
    processing read/write ioport commands if the selected floppy drive is not initialized with a block device.
    This flaw allows a privileged guest user to crash the QEMU process on the host, resulting in a denial of
    service. The highest threat from this vulnerability is to system availability. (CVE-2021-20196)

  - An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw
    exists in the udp6_input() function and could occur while processing a udp packet that is smaller than the
    size of the 'udphdr' structure. This issue may lead to out-of-bounds read access or indirect host memory
    disclosure to the guest. The highest threat from this vulnerability is to data confidentiality. This flaw
    affects libslirp versions prior to 4.6.0. (CVE-2021-3593)

  - A use-after-free vulnerability was found in the virtio-net device of QEMU. It could occur when the
    descriptor's address belongs to the non direct access region, due to num_buffers being set after the
    virtqueue elem has been unmapped. A malicious guest could use this flaw to crash QEMU, resulting in a
    denial of service condition, or potentially execute code on the host with the privileges of the QEMU
    process. (CVE-2021-3748)

  - An off-by-one error was found in the SCSI device emulation in QEMU. It could occur while processing MODE
    SELECT commands in mode_sense_page() if the 'page' argument was set to MODE_PAGE_ALLS (0x3f). A malicious
    guest could use this flaw to potentially crash QEMU, resulting in a denial of service condition.
    (CVE-2021-3930)

  - A flaw was found in the vhost-vsock device of QEMU. In case of error, an invalid element was not detached
    from the virtqueue before freeing its memory, leading to memory leakage and other unexpected results.
    Affected QEMU versions <= 6.2.0. (CVE-2022-26354)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/qemu");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2970");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20196");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3593");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3748");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3930");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26354");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/qemu");
  script_set_attribute(attribute:"solution", value:
"Upgrade the qemu packages.

For Debian 9 stretch, these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3748");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-block-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-sparc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user-binfmt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'qemu', 'reference': '1:2.8+dfsg-6+deb9u17'},
    {'release': '9.0', 'prefix': 'qemu-block-extra', 'reference': '1:2.8+dfsg-6+deb9u17'},
    {'release': '9.0', 'prefix': 'qemu-guest-agent', 'reference': '1:2.8+dfsg-6+deb9u17'},
    {'release': '9.0', 'prefix': 'qemu-kvm', 'reference': '1:2.8+dfsg-6+deb9u17'},
    {'release': '9.0', 'prefix': 'qemu-system', 'reference': '1:2.8+dfsg-6+deb9u17'},
    {'release': '9.0', 'prefix': 'qemu-system-arm', 'reference': '1:2.8+dfsg-6+deb9u17'},
    {'release': '9.0', 'prefix': 'qemu-system-common', 'reference': '1:2.8+dfsg-6+deb9u17'},
    {'release': '9.0', 'prefix': 'qemu-system-mips', 'reference': '1:2.8+dfsg-6+deb9u17'},
    {'release': '9.0', 'prefix': 'qemu-system-misc', 'reference': '1:2.8+dfsg-6+deb9u17'},
    {'release': '9.0', 'prefix': 'qemu-system-ppc', 'reference': '1:2.8+dfsg-6+deb9u17'},
    {'release': '9.0', 'prefix': 'qemu-system-sparc', 'reference': '1:2.8+dfsg-6+deb9u17'},
    {'release': '9.0', 'prefix': 'qemu-system-x86', 'reference': '1:2.8+dfsg-6+deb9u17'},
    {'release': '9.0', 'prefix': 'qemu-user', 'reference': '1:2.8+dfsg-6+deb9u17'},
    {'release': '9.0', 'prefix': 'qemu-user-binfmt', 'reference': '1:2.8+dfsg-6+deb9u17'},
    {'release': '9.0', 'prefix': 'qemu-user-static', 'reference': '1:2.8+dfsg-6+deb9u17'},
    {'release': '9.0', 'prefix': 'qemu-utils', 'reference': '1:2.8+dfsg-6+deb9u17'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu / qemu-block-extra / qemu-guest-agent / qemu-kvm / qemu-system / etc');
}
