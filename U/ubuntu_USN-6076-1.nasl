#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6076-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175821);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/16");

  script_cve_id(
    "CVE-2018-10657",
    "CVE-2018-12291",
    "CVE-2018-12423",
    "CVE-2018-16515",
    "CVE-2019-5885",
    "CVE-2019-11842",
    "CVE-2019-18835"
  );
  script_xref(name:"USN", value:"6076-1");

  script_name(english:"Ubuntu 18.04 ESM : Synapse vulnerabilities (USN-6076-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 ESM host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-6076-1 advisory.

  - Matrix Synapse before 0.28.1 is prone to a denial of service flaw where malicious events injected with
    depth = 2^63 - 1 render rooms unusable, related to federation/federation_base.py and handlers/message.py,
    as exploited in the wild in April 2018. (CVE-2018-10657)

  - The on_get_missing_events function in handlers/federation.py in Matrix Synapse before 0.31.1 has a
    security bug in the get_missing_events federation API where event visibility rules were not applied
    correctly. (CVE-2018-12291)

  - In Synapse before 0.31.2, unauthorised users can hijack rooms when there is no m.room.power_levels event
    in force. (CVE-2018-12423)

  - Matrix Synapse before 0.33.3.1 allows remote attackers to spoof events and possibly have unspecified other
    impacts by leveraging improper transaction and event signature validation. (CVE-2018-16515)

  - An issue was discovered in Matrix Sydent before 1.0.3 and Synapse before 0.99.3.1. Random number
    generation is mishandled, which makes it easier for attackers to predict a Sydent authentication token or
    a Synapse random ID. (CVE-2019-11842)

  - Matrix Synapse before 1.5.0 mishandles signature checking on some federation APIs. Events sent over
    /send_join, /send_leave, and /invite may not be correctly signed, or may not come from the expected
    servers. (CVE-2019-18835)

  - Matrix Synapse before 0.34.0.1, when the macaroon_secret_key authentication parameter is not set, uses a
    predictable value to derive a secret key and other secrets which could allow remote attackers to
    impersonate users. (CVE-2019-5885)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6076-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected matrix-synapse package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18835");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:matrix-synapse");
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
if (! preg(pattern:"^(18\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'matrix-synapse', 'pkgver': '0.24.0+dfsg-1ubuntu0.1~esm1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'matrix-synapse');
}
