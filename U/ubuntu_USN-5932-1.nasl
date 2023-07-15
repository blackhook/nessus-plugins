#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5932-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172241);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/08");

  script_cve_id(
    "CVE-2022-31001",
    "CVE-2022-31002",
    "CVE-2022-31003",
    "CVE-2022-47516",
    "CVE-2023-22741"
  );
  script_xref(name:"USN", value:"5932-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : Sofia-SIP vulnerabilities (USN-5932-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5932-1 advisory.

  - Sofia-SIP is an open-source Session Initiation Protocol (SIP) User-Agent library. Prior to version 1.13.8,
    an attacker can send a message with evil sdp to FreeSWITCH, which may cause crash. This type of crash may
    be caused by `#define MATCH(s, m) (strncmp(s, m, n = sizeof(m) - 1) == 0)`, which will make `n` bigger and
    trigger out-of-bound access when `IS_NON_WS(s[n])`. Version 1.13.8 contains a patch for this issue.
    (CVE-2022-31001)

  - Sofia-SIP is an open-source Session Initiation Protocol (SIP) User-Agent library. Prior to version 1.13.8,
    an attacker can send a message with evil sdp to FreeSWITCH, which may cause a crash. This type of crash
    may be caused by a URL ending with `%`. Version 1.13.8 contains a patch for this issue. (CVE-2022-31002)

  - Sofia-SIP is an open-source Session Initiation Protocol (SIP) User-Agent library. Prior to version 1.13.8,
    when parsing each line of a sdp message, `rest = record + 2` will access the memory behind `\0` and cause
    an out-of-bounds write. An attacker can send a message with evil sdp to FreeSWITCH, causing a crash or
    more serious consequence, such as remote code execution. Version 1.13.8 contains a patch for this issue.
    (CVE-2022-31003)

  - An issue was discovered in the libsofia-sip fork in drachtio-server before 0.8.20. It allows remote
    attackers to cause a denial of service (daemon crash) via a crafted UDP message that leads to a failure of
    the libsofia-sip-ua/tport/tport.c self assertion. (CVE-2022-47516)

  - Sofia-SIP is an open-source SIP User-Agent library, compliant with the IETF RFC3261 specification. In
    affected versions Sofia-SIP **lacks both message length and attributes length checks** when it handles
    STUN packets, leading to controllable heap-over-flow. For example, in stun_parse_attribute(), after we get
    the attribute's type and length value, the length will be used directly to copy from the heap, regardless
    of the message's left size. Since network users control the overflowed length, and the data is written to
    heap chunks later, attackers may achieve remote code execution by heap grooming or other exploitation
    methods. The bug was introduced 16 years ago in sofia-sip 1.12.4 (plus some patches through 12/21/2006) to
    in tree libs with git-svn-id: http://svn.freeswitch.org/svn/freeswitch/trunk@3774
    d0543943-73ff-0310-b7d9-9358b9ac24b2. Users are advised to upgrade. There are no known workarounds for
    this vulnerability. (CVE-2023-22741)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5932-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31003");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-22741");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsofia-sip-ua-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsofia-sip-ua-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsofia-sip-ua-glib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsofia-sip-ua0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sofia-sip-bin");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libsofia-sip-ua-dev', 'pkgver': '1.12.11+20110422.1-2.1+deb10u3ubuntu0.16.04.1~esm1'},
    {'osver': '16.04', 'pkgname': 'libsofia-sip-ua-glib-dev', 'pkgver': '1.12.11+20110422.1-2.1+deb10u3ubuntu0.16.04.1~esm1'},
    {'osver': '16.04', 'pkgname': 'libsofia-sip-ua-glib3', 'pkgver': '1.12.11+20110422.1-2.1+deb10u3ubuntu0.16.04.1~esm1'},
    {'osver': '16.04', 'pkgname': 'libsofia-sip-ua0', 'pkgver': '1.12.11+20110422.1-2.1+deb10u3ubuntu0.16.04.1~esm1'},
    {'osver': '16.04', 'pkgname': 'sofia-sip-bin', 'pkgver': '1.12.11+20110422.1-2.1+deb10u3ubuntu0.16.04.1~esm1'},
    {'osver': '18.04', 'pkgname': 'libsofia-sip-ua-dev', 'pkgver': '1.12.11+20110422.1-2.1+deb10u3build0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libsofia-sip-ua-glib-dev', 'pkgver': '1.12.11+20110422.1-2.1+deb10u3build0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libsofia-sip-ua-glib3', 'pkgver': '1.12.11+20110422.1-2.1+deb10u3build0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libsofia-sip-ua0', 'pkgver': '1.12.11+20110422.1-2.1+deb10u3build0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'sofia-sip-bin', 'pkgver': '1.12.11+20110422.1-2.1+deb10u3build0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'libsofia-sip-ua-dev', 'pkgver': '1.12.11+20110422.1-2.1+deb10u3ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libsofia-sip-ua-glib-dev', 'pkgver': '1.12.11+20110422.1-2.1+deb10u3ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libsofia-sip-ua-glib3', 'pkgver': '1.12.11+20110422.1-2.1+deb10u3ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libsofia-sip-ua0', 'pkgver': '1.12.11+20110422.1-2.1+deb10u3ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'sofia-sip-bin', 'pkgver': '1.12.11+20110422.1-2.1+deb10u3ubuntu0.20.04.1'},
    {'osver': '22.04', 'pkgname': 'libsofia-sip-ua-dev', 'pkgver': '1.12.11+20110422.1-2.1+deb10u3ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libsofia-sip-ua-glib-dev', 'pkgver': '1.12.11+20110422.1-2.1+deb10u3ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libsofia-sip-ua-glib3', 'pkgver': '1.12.11+20110422.1-2.1+deb10u3ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libsofia-sip-ua0', 'pkgver': '1.12.11+20110422.1-2.1+deb10u3ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'sofia-sip-bin', 'pkgver': '1.12.11+20110422.1-2.1+deb10u3ubuntu0.22.04.1'},
    {'osver': '22.10', 'pkgname': 'libsofia-sip-ua-dev', 'pkgver': '1.12.11+20110422.1+1e14eea~dfsg-3ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libsofia-sip-ua-glib-dev', 'pkgver': '1.12.11+20110422.1+1e14eea~dfsg-3ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libsofia-sip-ua-glib3', 'pkgver': '1.12.11+20110422.1+1e14eea~dfsg-3ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libsofia-sip-ua0', 'pkgver': '1.12.11+20110422.1+1e14eea~dfsg-3ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'sofia-sip-bin', 'pkgver': '1.12.11+20110422.1+1e14eea~dfsg-3ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsofia-sip-ua-dev / libsofia-sip-ua-glib-dev / libsofia-sip-ua-glib3 / etc');
}
