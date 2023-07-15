##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4725-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146303);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-11947",
    "CVE-2020-15859",
    "CVE-2020-27821",
    "CVE-2020-28916",
    "CVE-2020-29443",
    "CVE-2021-20181"
  );
  script_xref(name:"USN", value:"4725-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 : QEMU vulnerabilities (USN-4725-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4725-1 advisory.

  - iscsi_aio_ioctl_cb in block/iscsi.c in QEMU 4.1.0 has a heap-based buffer over-read that may disclose
    unrelated information from process memory to an attacker. (CVE-2020-11947)

  - QEMU 4.2.0 has a use-after-free in hw/net/e1000e_core.c because a guest OS user can trigger an e1000e
    packet with the data's address set to the e1000e's MMIO address. (CVE-2020-15859)

  - A flaw was found in the memory management API of QEMU during the initialization of a memory region cache.
    This issue could lead to an out-of-bounds write access to the MSI-X table while performing MMIO
    operations. A guest user may abuse this flaw to crash the QEMU process on the host, resulting in a denial
    of service. This flaw affects QEMU versions prior to 5.2.0. (CVE-2020-27821)

  - hw/net/e1000e_core.c in QEMU 5.0.0 has an infinite loop via an RX descriptor with a NULL buffer address.
    (CVE-2020-28916)

  - ide_atapi_cmd_reply_end in hw/ide/atapi.c in QEMU 5.1.0 allows out-of-bounds read access because a buffer
    index is not validated. (CVE-2020-29443)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4725-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20181");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-block-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-sparc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86-microvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-user-binfmt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-user-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-utils");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(16\.04|18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'qemu', 'pkgver': '1:2.5+dfsg-5ubuntu10.49'},
    {'osver': '16.04', 'pkgname': 'qemu-block-extra', 'pkgver': '1:2.5+dfsg-5ubuntu10.49'},
    {'osver': '16.04', 'pkgname': 'qemu-guest-agent', 'pkgver': '1:2.5+dfsg-5ubuntu10.49'},
    {'osver': '16.04', 'pkgname': 'qemu-kvm', 'pkgver': '1:2.5+dfsg-5ubuntu10.49'},
    {'osver': '16.04', 'pkgname': 'qemu-system', 'pkgver': '1:2.5+dfsg-5ubuntu10.49'},
    {'osver': '16.04', 'pkgname': 'qemu-system-aarch64', 'pkgver': '1:2.5+dfsg-5ubuntu10.49'},
    {'osver': '16.04', 'pkgname': 'qemu-system-arm', 'pkgver': '1:2.5+dfsg-5ubuntu10.49'},
    {'osver': '16.04', 'pkgname': 'qemu-system-common', 'pkgver': '1:2.5+dfsg-5ubuntu10.49'},
    {'osver': '16.04', 'pkgname': 'qemu-system-mips', 'pkgver': '1:2.5+dfsg-5ubuntu10.49'},
    {'osver': '16.04', 'pkgname': 'qemu-system-misc', 'pkgver': '1:2.5+dfsg-5ubuntu10.49'},
    {'osver': '16.04', 'pkgname': 'qemu-system-ppc', 'pkgver': '1:2.5+dfsg-5ubuntu10.49'},
    {'osver': '16.04', 'pkgname': 'qemu-system-s390x', 'pkgver': '1:2.5+dfsg-5ubuntu10.49'},
    {'osver': '16.04', 'pkgname': 'qemu-system-sparc', 'pkgver': '1:2.5+dfsg-5ubuntu10.49'},
    {'osver': '16.04', 'pkgname': 'qemu-system-x86', 'pkgver': '1:2.5+dfsg-5ubuntu10.49'},
    {'osver': '16.04', 'pkgname': 'qemu-user', 'pkgver': '1:2.5+dfsg-5ubuntu10.49'},
    {'osver': '16.04', 'pkgname': 'qemu-user-binfmt', 'pkgver': '1:2.5+dfsg-5ubuntu10.49'},
    {'osver': '16.04', 'pkgname': 'qemu-user-static', 'pkgver': '1:2.5+dfsg-5ubuntu10.49'},
    {'osver': '16.04', 'pkgname': 'qemu-utils', 'pkgver': '1:2.5+dfsg-5ubuntu10.49'},
    {'osver': '18.04', 'pkgname': 'qemu', 'pkgver': '1:2.11+dfsg-1ubuntu7.35'},
    {'osver': '18.04', 'pkgname': 'qemu-block-extra', 'pkgver': '1:2.11+dfsg-1ubuntu7.35'},
    {'osver': '18.04', 'pkgname': 'qemu-guest-agent', 'pkgver': '1:2.11+dfsg-1ubuntu7.35'},
    {'osver': '18.04', 'pkgname': 'qemu-kvm', 'pkgver': '1:2.11+dfsg-1ubuntu7.35'},
    {'osver': '18.04', 'pkgname': 'qemu-system', 'pkgver': '1:2.11+dfsg-1ubuntu7.35'},
    {'osver': '18.04', 'pkgname': 'qemu-system-arm', 'pkgver': '1:2.11+dfsg-1ubuntu7.35'},
    {'osver': '18.04', 'pkgname': 'qemu-system-common', 'pkgver': '1:2.11+dfsg-1ubuntu7.35'},
    {'osver': '18.04', 'pkgname': 'qemu-system-mips', 'pkgver': '1:2.11+dfsg-1ubuntu7.35'},
    {'osver': '18.04', 'pkgname': 'qemu-system-misc', 'pkgver': '1:2.11+dfsg-1ubuntu7.35'},
    {'osver': '18.04', 'pkgname': 'qemu-system-ppc', 'pkgver': '1:2.11+dfsg-1ubuntu7.35'},
    {'osver': '18.04', 'pkgname': 'qemu-system-s390x', 'pkgver': '1:2.11+dfsg-1ubuntu7.35'},
    {'osver': '18.04', 'pkgname': 'qemu-system-sparc', 'pkgver': '1:2.11+dfsg-1ubuntu7.35'},
    {'osver': '18.04', 'pkgname': 'qemu-system-x86', 'pkgver': '1:2.11+dfsg-1ubuntu7.35'},
    {'osver': '18.04', 'pkgname': 'qemu-user', 'pkgver': '1:2.11+dfsg-1ubuntu7.35'},
    {'osver': '18.04', 'pkgname': 'qemu-user-binfmt', 'pkgver': '1:2.11+dfsg-1ubuntu7.35'},
    {'osver': '18.04', 'pkgname': 'qemu-user-static', 'pkgver': '1:2.11+dfsg-1ubuntu7.35'},
    {'osver': '18.04', 'pkgname': 'qemu-utils', 'pkgver': '1:2.11+dfsg-1ubuntu7.35'},
    {'osver': '20.04', 'pkgname': 'qemu', 'pkgver': '1:4.2-3ubuntu6.12'},
    {'osver': '20.04', 'pkgname': 'qemu-block-extra', 'pkgver': '1:4.2-3ubuntu6.12'},
    {'osver': '20.04', 'pkgname': 'qemu-guest-agent', 'pkgver': '1:4.2-3ubuntu6.12'},
    {'osver': '20.04', 'pkgname': 'qemu-kvm', 'pkgver': '1:4.2-3ubuntu6.12'},
    {'osver': '20.04', 'pkgname': 'qemu-system', 'pkgver': '1:4.2-3ubuntu6.12'},
    {'osver': '20.04', 'pkgname': 'qemu-system-arm', 'pkgver': '1:4.2-3ubuntu6.12'},
    {'osver': '20.04', 'pkgname': 'qemu-system-common', 'pkgver': '1:4.2-3ubuntu6.12'},
    {'osver': '20.04', 'pkgname': 'qemu-system-data', 'pkgver': '1:4.2-3ubuntu6.12'},
    {'osver': '20.04', 'pkgname': 'qemu-system-gui', 'pkgver': '1:4.2-3ubuntu6.12'},
    {'osver': '20.04', 'pkgname': 'qemu-system-mips', 'pkgver': '1:4.2-3ubuntu6.12'},
    {'osver': '20.04', 'pkgname': 'qemu-system-misc', 'pkgver': '1:4.2-3ubuntu6.12'},
    {'osver': '20.04', 'pkgname': 'qemu-system-ppc', 'pkgver': '1:4.2-3ubuntu6.12'},
    {'osver': '20.04', 'pkgname': 'qemu-system-s390x', 'pkgver': '1:4.2-3ubuntu6.12'},
    {'osver': '20.04', 'pkgname': 'qemu-system-sparc', 'pkgver': '1:4.2-3ubuntu6.12'},
    {'osver': '20.04', 'pkgname': 'qemu-system-x86', 'pkgver': '1:4.2-3ubuntu6.12'},
    {'osver': '20.04', 'pkgname': 'qemu-system-x86-microvm', 'pkgver': '1:4.2-3ubuntu6.12'},
    {'osver': '20.04', 'pkgname': 'qemu-system-x86-xen', 'pkgver': '1:4.2-3ubuntu6.12'},
    {'osver': '20.04', 'pkgname': 'qemu-user', 'pkgver': '1:4.2-3ubuntu6.12'},
    {'osver': '20.04', 'pkgname': 'qemu-user-binfmt', 'pkgver': '1:4.2-3ubuntu6.12'},
    {'osver': '20.04', 'pkgname': 'qemu-user-static', 'pkgver': '1:4.2-3ubuntu6.12'},
    {'osver': '20.04', 'pkgname': 'qemu-utils', 'pkgver': '1:4.2-3ubuntu6.12'},
    {'osver': '20.10', 'pkgname': 'qemu', 'pkgver': '1:5.0-5ubuntu9.4'},
    {'osver': '20.10', 'pkgname': 'qemu-block-extra', 'pkgver': '1:5.0-5ubuntu9.4'},
    {'osver': '20.10', 'pkgname': 'qemu-guest-agent', 'pkgver': '1:5.0-5ubuntu9.4'},
    {'osver': '20.10', 'pkgname': 'qemu-kvm', 'pkgver': '1:5.0-5ubuntu9.4'},
    {'osver': '20.10', 'pkgname': 'qemu-system', 'pkgver': '1:5.0-5ubuntu9.4'},
    {'osver': '20.10', 'pkgname': 'qemu-system-arm', 'pkgver': '1:5.0-5ubuntu9.4'},
    {'osver': '20.10', 'pkgname': 'qemu-system-common', 'pkgver': '1:5.0-5ubuntu9.4'},
    {'osver': '20.10', 'pkgname': 'qemu-system-data', 'pkgver': '1:5.0-5ubuntu9.4'},
    {'osver': '20.10', 'pkgname': 'qemu-system-gui', 'pkgver': '1:5.0-5ubuntu9.4'},
    {'osver': '20.10', 'pkgname': 'qemu-system-mips', 'pkgver': '1:5.0-5ubuntu9.4'},
    {'osver': '20.10', 'pkgname': 'qemu-system-misc', 'pkgver': '1:5.0-5ubuntu9.4'},
    {'osver': '20.10', 'pkgname': 'qemu-system-ppc', 'pkgver': '1:5.0-5ubuntu9.4'},
    {'osver': '20.10', 'pkgname': 'qemu-system-s390x', 'pkgver': '1:5.0-5ubuntu9.4'},
    {'osver': '20.10', 'pkgname': 'qemu-system-sparc', 'pkgver': '1:5.0-5ubuntu9.4'},
    {'osver': '20.10', 'pkgname': 'qemu-system-x86', 'pkgver': '1:5.0-5ubuntu9.4'},
    {'osver': '20.10', 'pkgname': 'qemu-system-x86-microvm', 'pkgver': '1:5.0-5ubuntu9.4'},
    {'osver': '20.10', 'pkgname': 'qemu-system-x86-xen', 'pkgver': '1:5.0-5ubuntu9.4'},
    {'osver': '20.10', 'pkgname': 'qemu-user', 'pkgver': '1:5.0-5ubuntu9.4'},
    {'osver': '20.10', 'pkgname': 'qemu-user-binfmt', 'pkgver': '1:5.0-5ubuntu9.4'},
    {'osver': '20.10', 'pkgname': 'qemu-user-static', 'pkgver': '1:5.0-5ubuntu9.4'},
    {'osver': '20.10', 'pkgname': 'qemu-utils', 'pkgver': '1:5.0-5ubuntu9.4'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu / qemu-block-extra / qemu-guest-agent / qemu-kvm / qemu-system / etc');
}