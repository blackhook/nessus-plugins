#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6121-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176490);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/30");

  script_cve_id("CVE-2020-26243", "CVE-2021-21401");
  script_xref(name:"USN", value:"6121-1");

  script_name(english:"Ubuntu 20.04 ESM : Nanopb vulnerabilities (USN-6121-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 ESM host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-6121-1 advisory.

  - Nanopb is a small code-size Protocol Buffers implementation. In Nanopb before versions 0.4.4 and 0.3.9.7,
    decoding specifically formed message can leak memory if dynamic allocation is enabled and an oneof field
    contains a static submessage that contains a dynamic field, and the message being decoded contains the
    submessage multiple times. This is rare in normal messages, but it is a concern when untrusted data is
    parsed. This is fixed in versions 0.3.9.7 and 0.4.4. The following workarounds are available: 1) Set the
    option `no_unions` for the oneof field. This will generate fields as separate instead of C union, and
    avoids triggering the problematic code. 2) Set the type of the submessage field inside oneof to
    `FT_POINTER`. This way the whole submessage will be dynamically allocated and the problematic code is not
    executed. 3) Use an arena allocator for nanopb, to make sure all memory can be released afterwards.
    (CVE-2020-26243)

  - Nanopb is a small code-size Protocol Buffers implementation in ansi C. In Nanopb before versions 0.3.9.8
    and 0.4.5, decoding a specifically formed message can cause invalid `free()` or `realloc()` calls if the
    message type contains an `oneof` field, and the `oneof` directly contains both a pointer field and a non-
    pointer field. If the message data first contains the non-pointer field and then the pointer field, the
    data of the non-pointer field is incorrectly treated as if it was a pointer value. Such message data
    rarely occurs in normal messages, but it is a concern when untrusted data is parsed. This has been fixed
    in versions 0.3.9.8 and 0.4.5. See referenced GitHub Security Advisory for more information including
    workarounds. (CVE-2021-21401)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6121-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected libnanopb-dev and / or nanopb packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21401");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnanopb-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nanopb");
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
if (! preg(pattern:"^(20\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'libnanopb-dev', 'pkgver': '0.4.1-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'nanopb', 'pkgver': '0.4.1-1ubuntu0.1~esm1'}
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
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnanopb-dev / nanopb');
}
