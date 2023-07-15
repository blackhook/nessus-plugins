#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5133. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(160887);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2021-4206",
    "CVE-2021-4207",
    "CVE-2022-0358",
    "CVE-2022-26353",
    "CVE-2022-26354"
  );

  script_name(english:"Debian DSA-5133-1 : qemu - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5133 advisory.

  - A flaw was found in the QXL display device emulation in QEMU. A double fetch of guest controlled values
    `cursor->header.width` and `cursor->header.height` can lead to the allocation of a small cursor object
    followed by a subsequent heap-based buffer overflow. A malicious privileged guest user could use this flaw
    to crash the QEMU process on the host or potentially execute arbitrary code within the context of the QEMU
    process. (CVE-2021-4207)

  - A flaw was found in the QXL display device emulation in QEMU. An integer overflow in the cursor_alloc()
    function can lead to the allocation of a small cursor object followed by a subsequent heap-based buffer
    overflow. This flaw allows a malicious privileged guest user to crash the QEMU process on the host or
    potentially execute arbitrary code within the context of the QEMU process. (CVE-2021-4206)

  - A flaw was found in the QEMU virtio-fs shared file system daemon (virtiofsd) implementation. This flaw is
    strictly related to CVE-2018-13405. A local guest user can create files in the directories shared by
    virtio-fs with unintended group ownership in a scenario where a directory is SGID to a certain group and
    is writable by a user who is not a member of the group. This could allow a malicious unprivileged user
    inside the guest to gain access to resources accessible to the root group, potentially escalating their
    privileges within the guest. A malicious local user in the host might also leverage this unexpected
    executable file created by the guest to escalate their privileges on the host system. (CVE-2022-0358)

  - A flaw was found in the virtio-net device of QEMU. This flaw was inadvertently introduced with the fix for
    CVE-2021-3748, which forgot to unmap the cached virtqueue elements on error, leading to memory leakage and
    other unexpected results. Affected QEMU version: 6.2.0. (CVE-2022-26353)

  - A flaw was found in the vhost-vsock device of QEMU. In case of error, an invalid element was not detached
    from the virtqueue before freeing its memory, leading to memory leakage and other unexpected results.
    Affected QEMU versions <= 6.2.0. (CVE-2022-26354)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/qemu");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5133");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4206");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4207");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0358");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26353");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26354");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/qemu");
  script_set_attribute(attribute:"solution", value:
"Upgrade the qemu packages.

For the stable distribution (bullseye), this problem has been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4207");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-block-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-sparc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user-binfmt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'qemu', 'reference': '1:5.2+dfsg-11+deb11u2'},
    {'release': '11.0', 'prefix': 'qemu-block-extra', 'reference': '1:5.2+dfsg-11+deb11u2'},
    {'release': '11.0', 'prefix': 'qemu-guest-agent', 'reference': '1:5.2+dfsg-11+deb11u2'},
    {'release': '11.0', 'prefix': 'qemu-system', 'reference': '1:5.2+dfsg-11+deb11u2'},
    {'release': '11.0', 'prefix': 'qemu-system-arm', 'reference': '1:5.2+dfsg-11+deb11u2'},
    {'release': '11.0', 'prefix': 'qemu-system-common', 'reference': '1:5.2+dfsg-11+deb11u2'},
    {'release': '11.0', 'prefix': 'qemu-system-data', 'reference': '1:5.2+dfsg-11+deb11u2'},
    {'release': '11.0', 'prefix': 'qemu-system-gui', 'reference': '1:5.2+dfsg-11+deb11u2'},
    {'release': '11.0', 'prefix': 'qemu-system-mips', 'reference': '1:5.2+dfsg-11+deb11u2'},
    {'release': '11.0', 'prefix': 'qemu-system-misc', 'reference': '1:5.2+dfsg-11+deb11u2'},
    {'release': '11.0', 'prefix': 'qemu-system-ppc', 'reference': '1:5.2+dfsg-11+deb11u2'},
    {'release': '11.0', 'prefix': 'qemu-system-sparc', 'reference': '1:5.2+dfsg-11+deb11u2'},
    {'release': '11.0', 'prefix': 'qemu-system-x86', 'reference': '1:5.2+dfsg-11+deb11u2'},
    {'release': '11.0', 'prefix': 'qemu-user', 'reference': '1:5.2+dfsg-11+deb11u2'},
    {'release': '11.0', 'prefix': 'qemu-user-binfmt', 'reference': '1:5.2+dfsg-11+deb11u2'},
    {'release': '11.0', 'prefix': 'qemu-user-static', 'reference': '1:5.2+dfsg-11+deb11u2'},
    {'release': '11.0', 'prefix': 'qemu-utils', 'reference': '1:5.2+dfsg-11+deb11u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu / qemu-block-extra / qemu-guest-agent / qemu-system / etc');
}
