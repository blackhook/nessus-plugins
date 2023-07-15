#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5778-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171576);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id(
    "CVE-2022-4283",
    "CVE-2022-46340",
    "CVE-2022-46341",
    "CVE-2022-46342",
    "CVE-2022-46343",
    "CVE-2022-46344",
    "CVE-2023-0494"
  );
  script_xref(name:"USN", value:"5778-2");

  script_name(english:"Ubuntu 16.04 ESM : X.Org X Server vulnerabilities (USN-5778-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5778-2 advisory.

  - A vulnerability was found in X.Org. This security flaw occurs because the XkbCopyNames function left a
    dangling pointer to freed memory, resulting in out-of-bounds memory access on subsequent XkbGetKbdByName
    requests.. This issue can lead to local privileges elevation on systems where the X server is running
    privileged and remote code execution for ssh X forwarding sessions. (CVE-2022-4283)

  - A vulnerability was found in X.Org. This security flaw occurs becuase the swap handler for the
    XTestFakeInput request of the XTest extension may corrupt the stack if GenericEvents with lengths larger
    than 32 bytes are sent through a the XTestFakeInput request. This issue can lead to local privileges
    elevation on systems where the X server is running privileged and remote code execution for ssh X
    forwarding sessions. This issue does not affect systems where client and server use the same byte order.
    (CVE-2022-46340)

  - A vulnerability was found in X.Org. This security flaw occurs because the handler for the XIPassiveUngrab
    request accesses out-of-bounds memory when invoked with a high keycode or button code. This issue can lead
    to local privileges elevation on systems where the X server is running privileged and remote code
    execution for ssh X forwarding sessions. (CVE-2022-46341)

  - A vulnerability was found in X.Org. This security flaw occurs because the handler for the
    XvdiSelectVideoNotify request may write to memory after it has been freed. This issue can lead to local
    privileges elevation on systems where the X se (CVE-2022-46342)

  - A vulnerability was found in X.Org. This security flaw occurs because the handler for the
    ScreenSaverSetAttributes request may write to memory after it has been freed. This issue can lead to local
    privileges elevation on systems where the X server is running privileged and remote code execution for ssh
    X forwarding sessions. (CVE-2022-46343)

  - A vulnerability was found in X.Org. This security flaw occurs because the handler for the XIChangeProperty
    request has a length-validation issues, resulting in out-of-bounds memory reads and potential information
    disclosure. This issue can lead to local privileges elevation on systems where the X server is running
    privileged and remote code execution for ssh X forwarding sessions. (CVE-2022-46344)

  - xorg-x11-server: DeepCopyPointerClasses use-after-free leads to privilege elevation (CVE-2023-0494)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5778-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-46344");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdmx-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xmir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xmir-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-server-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-server-source-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xephyr-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-dev-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-legacy-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-xmir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xwayland-hwe-16.04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! preg(pattern:"^(16\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'xdmx', 'pkgver': '2:1.18.4-0ubuntu0.12+esm5'},
    {'osver': '16.04', 'pkgname': 'xdmx-tools', 'pkgver': '2:1.18.4-0ubuntu0.12+esm5'},
    {'osver': '16.04', 'pkgname': 'xmir', 'pkgver': '2:1.18.4-0ubuntu0.12+esm5'},
    {'osver': '16.04', 'pkgname': 'xmir-hwe-16.04', 'pkgver': '2:1.19.6-1ubuntu4.1~16.04.6+esm4'},
    {'osver': '16.04', 'pkgname': 'xnest', 'pkgver': '2:1.18.4-0ubuntu0.12+esm5'},
    {'osver': '16.04', 'pkgname': 'xorg-server-source', 'pkgver': '2:1.18.4-0ubuntu0.12+esm5'},
    {'osver': '16.04', 'pkgname': 'xorg-server-source-hwe-16.04', 'pkgver': '2:1.19.6-1ubuntu4.1~16.04.6+esm4'},
    {'osver': '16.04', 'pkgname': 'xserver-common', 'pkgver': '2:1.18.4-0ubuntu0.12+esm5'},
    {'osver': '16.04', 'pkgname': 'xserver-xephyr', 'pkgver': '2:1.18.4-0ubuntu0.12+esm5'},
    {'osver': '16.04', 'pkgname': 'xserver-xephyr-hwe-16.04', 'pkgver': '2:1.19.6-1ubuntu4.1~16.04.6+esm4'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-core', 'pkgver': '2:1.18.4-0ubuntu0.12+esm5'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-core-hwe-16.04', 'pkgver': '2:1.19.6-1ubuntu4.1~16.04.6+esm4'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-dev', 'pkgver': '2:1.18.4-0ubuntu0.12+esm5'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-dev-hwe-16.04', 'pkgver': '2:1.19.6-1ubuntu4.1~16.04.6+esm4'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-legacy', 'pkgver': '2:1.18.4-0ubuntu0.12+esm5'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-legacy-hwe-16.04', 'pkgver': '2:1.19.6-1ubuntu4.1~16.04.6+esm4'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-xmir', 'pkgver': '2:1.18.4-0ubuntu0.12+esm5'},
    {'osver': '16.04', 'pkgname': 'xvfb', 'pkgver': '2:1.18.4-0ubuntu0.12+esm5'},
    {'osver': '16.04', 'pkgname': 'xwayland', 'pkgver': '2:1.18.4-0ubuntu0.12+esm5'},
    {'osver': '16.04', 'pkgname': 'xwayland-hwe-16.04', 'pkgver': '2:1.19.6-1ubuntu4.1~16.04.6+esm4'}
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
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xdmx / xdmx-tools / xmir / xmir-hwe-16.04 / xnest / xorg-server-source / etc');
}
