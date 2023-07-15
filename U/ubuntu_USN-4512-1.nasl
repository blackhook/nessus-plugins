#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4512-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140648);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2018-7738");
  script_bugtraq_id(103367);
  script_xref(name:"USN", value:"4512-1");

  script_name(english:"Ubuntu 18.04 LTS : util-linux vulnerability (USN-4512-1)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-4512-1 advisory.

  - In util-linux before 2.32-rc1, bash-completion/umount allows local users to gain privileges by embedding
    shell commands in a mountpoint name, which is mishandled during a umount command (within Bash) by a
    different user, as demonstrated by logging in as root and entering umount followed by a tab character for
    autocompletion. (CVE-2018-7738)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4512-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7738");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bsdutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fdisk-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libblkid-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libblkid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libblkid1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfdisk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfdisk1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfdisk1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmount-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmount1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmount1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmartcols-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmartcols1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmartcols1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuuid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuuid1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rfkill");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:setpriv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:util-linux-locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:util-linux-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uuid-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uuid-runtime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(18\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'bsdutils', 'pkgver': '1:2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'fdisk', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'fdisk-udeb', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'libblkid-dev', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'libblkid1', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'libblkid1-udeb', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'libfdisk-dev', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'libfdisk1', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'libfdisk1-udeb', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'libmount-dev', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'libmount1', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'libmount1-udeb', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'libsmartcols-dev', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'libsmartcols1', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'libsmartcols1-udeb', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'libuuid1', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'libuuid1-udeb', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'mount', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'rfkill', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'setpriv', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'util-linux', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'util-linux-locales', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'util-linux-udeb', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'uuid-dev', 'pkgver': '2.31.1-0.4ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'uuid-runtime', 'pkgver': '2.31.1-0.4ubuntu3.7'}
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
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bsdutils / fdisk / fdisk-udeb / libblkid-dev / libblkid1 / etc');
}
