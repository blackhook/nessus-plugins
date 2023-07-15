##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4467-3. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147981);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");
  script_xref(name:"USN", value:"4467-3");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS : QEMU regression (USN-4467-3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS host has packages installed that are affected by a vulnerability as
referenced in the USN-4467-3 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4467-3");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
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
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(16\.04|18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '16.04', 'pkgname': 'qemu', 'pkgver': '1:2.5+dfsg-5ubuntu10.51'},
    {'osver': '16.04', 'pkgname': 'qemu-block-extra', 'pkgver': '1:2.5+dfsg-5ubuntu10.51'},
    {'osver': '16.04', 'pkgname': 'qemu-guest-agent', 'pkgver': '1:2.5+dfsg-5ubuntu10.51'},
    {'osver': '16.04', 'pkgname': 'qemu-kvm', 'pkgver': '1:2.5+dfsg-5ubuntu10.51'},
    {'osver': '16.04', 'pkgname': 'qemu-system', 'pkgver': '1:2.5+dfsg-5ubuntu10.51'},
    {'osver': '16.04', 'pkgname': 'qemu-system-aarch64', 'pkgver': '1:2.5+dfsg-5ubuntu10.51'},
    {'osver': '16.04', 'pkgname': 'qemu-system-arm', 'pkgver': '1:2.5+dfsg-5ubuntu10.51'},
    {'osver': '16.04', 'pkgname': 'qemu-system-common', 'pkgver': '1:2.5+dfsg-5ubuntu10.51'},
    {'osver': '16.04', 'pkgname': 'qemu-system-mips', 'pkgver': '1:2.5+dfsg-5ubuntu10.51'},
    {'osver': '16.04', 'pkgname': 'qemu-system-misc', 'pkgver': '1:2.5+dfsg-5ubuntu10.51'},
    {'osver': '16.04', 'pkgname': 'qemu-system-ppc', 'pkgver': '1:2.5+dfsg-5ubuntu10.51'},
    {'osver': '16.04', 'pkgname': 'qemu-system-s390x', 'pkgver': '1:2.5+dfsg-5ubuntu10.51'},
    {'osver': '16.04', 'pkgname': 'qemu-system-sparc', 'pkgver': '1:2.5+dfsg-5ubuntu10.51'},
    {'osver': '16.04', 'pkgname': 'qemu-system-x86', 'pkgver': '1:2.5+dfsg-5ubuntu10.51'},
    {'osver': '16.04', 'pkgname': 'qemu-user', 'pkgver': '1:2.5+dfsg-5ubuntu10.51'},
    {'osver': '16.04', 'pkgname': 'qemu-user-binfmt', 'pkgver': '1:2.5+dfsg-5ubuntu10.51'},
    {'osver': '16.04', 'pkgname': 'qemu-user-static', 'pkgver': '1:2.5+dfsg-5ubuntu10.51'},
    {'osver': '16.04', 'pkgname': 'qemu-utils', 'pkgver': '1:2.5+dfsg-5ubuntu10.51'},
    {'osver': '18.04', 'pkgname': 'qemu', 'pkgver': '1:2.11+dfsg-1ubuntu7.36'},
    {'osver': '18.04', 'pkgname': 'qemu-block-extra', 'pkgver': '1:2.11+dfsg-1ubuntu7.36'},
    {'osver': '18.04', 'pkgname': 'qemu-guest-agent', 'pkgver': '1:2.11+dfsg-1ubuntu7.36'},
    {'osver': '18.04', 'pkgname': 'qemu-kvm', 'pkgver': '1:2.11+dfsg-1ubuntu7.36'},
    {'osver': '18.04', 'pkgname': 'qemu-system', 'pkgver': '1:2.11+dfsg-1ubuntu7.36'},
    {'osver': '18.04', 'pkgname': 'qemu-system-arm', 'pkgver': '1:2.11+dfsg-1ubuntu7.36'},
    {'osver': '18.04', 'pkgname': 'qemu-system-common', 'pkgver': '1:2.11+dfsg-1ubuntu7.36'},
    {'osver': '18.04', 'pkgname': 'qemu-system-mips', 'pkgver': '1:2.11+dfsg-1ubuntu7.36'},
    {'osver': '18.04', 'pkgname': 'qemu-system-misc', 'pkgver': '1:2.11+dfsg-1ubuntu7.36'},
    {'osver': '18.04', 'pkgname': 'qemu-system-ppc', 'pkgver': '1:2.11+dfsg-1ubuntu7.36'},
    {'osver': '18.04', 'pkgname': 'qemu-system-s390x', 'pkgver': '1:2.11+dfsg-1ubuntu7.36'},
    {'osver': '18.04', 'pkgname': 'qemu-system-sparc', 'pkgver': '1:2.11+dfsg-1ubuntu7.36'},
    {'osver': '18.04', 'pkgname': 'qemu-system-x86', 'pkgver': '1:2.11+dfsg-1ubuntu7.36'},
    {'osver': '18.04', 'pkgname': 'qemu-user', 'pkgver': '1:2.11+dfsg-1ubuntu7.36'},
    {'osver': '18.04', 'pkgname': 'qemu-user-binfmt', 'pkgver': '1:2.11+dfsg-1ubuntu7.36'},
    {'osver': '18.04', 'pkgname': 'qemu-user-static', 'pkgver': '1:2.11+dfsg-1ubuntu7.36'},
    {'osver': '18.04', 'pkgname': 'qemu-utils', 'pkgver': '1:2.11+dfsg-1ubuntu7.36'},
    {'osver': '20.04', 'pkgname': 'qemu', 'pkgver': '1:4.2-3ubuntu6.14'},
    {'osver': '20.04', 'pkgname': 'qemu-block-extra', 'pkgver': '1:4.2-3ubuntu6.14'},
    {'osver': '20.04', 'pkgname': 'qemu-guest-agent', 'pkgver': '1:4.2-3ubuntu6.14'},
    {'osver': '20.04', 'pkgname': 'qemu-kvm', 'pkgver': '1:4.2-3ubuntu6.14'},
    {'osver': '20.04', 'pkgname': 'qemu-system', 'pkgver': '1:4.2-3ubuntu6.14'},
    {'osver': '20.04', 'pkgname': 'qemu-system-arm', 'pkgver': '1:4.2-3ubuntu6.14'},
    {'osver': '20.04', 'pkgname': 'qemu-system-common', 'pkgver': '1:4.2-3ubuntu6.14'},
    {'osver': '20.04', 'pkgname': 'qemu-system-data', 'pkgver': '1:4.2-3ubuntu6.14'},
    {'osver': '20.04', 'pkgname': 'qemu-system-gui', 'pkgver': '1:4.2-3ubuntu6.14'},
    {'osver': '20.04', 'pkgname': 'qemu-system-mips', 'pkgver': '1:4.2-3ubuntu6.14'},
    {'osver': '20.04', 'pkgname': 'qemu-system-misc', 'pkgver': '1:4.2-3ubuntu6.14'},
    {'osver': '20.04', 'pkgname': 'qemu-system-ppc', 'pkgver': '1:4.2-3ubuntu6.14'},
    {'osver': '20.04', 'pkgname': 'qemu-system-s390x', 'pkgver': '1:4.2-3ubuntu6.14'},
    {'osver': '20.04', 'pkgname': 'qemu-system-sparc', 'pkgver': '1:4.2-3ubuntu6.14'},
    {'osver': '20.04', 'pkgname': 'qemu-system-x86', 'pkgver': '1:4.2-3ubuntu6.14'},
    {'osver': '20.04', 'pkgname': 'qemu-system-x86-microvm', 'pkgver': '1:4.2-3ubuntu6.14'},
    {'osver': '20.04', 'pkgname': 'qemu-system-x86-xen', 'pkgver': '1:4.2-3ubuntu6.14'},
    {'osver': '20.04', 'pkgname': 'qemu-user', 'pkgver': '1:4.2-3ubuntu6.14'},
    {'osver': '20.04', 'pkgname': 'qemu-user-binfmt', 'pkgver': '1:4.2-3ubuntu6.14'},
    {'osver': '20.04', 'pkgname': 'qemu-user-static', 'pkgver': '1:4.2-3ubuntu6.14'},
    {'osver': '20.04', 'pkgname': 'qemu-utils', 'pkgver': '1:4.2-3ubuntu6.14'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
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
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu / qemu-block-extra / qemu-guest-agent / qemu-kvm / qemu-system / etc');
}
