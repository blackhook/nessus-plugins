#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4943-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149408);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-26217",
    "CVE-2020-26258",
    "CVE-2020-26259",
    "CVE-2021-21341",
    "CVE-2021-21342",
    "CVE-2021-21343",
    "CVE-2021-21344",
    "CVE-2021-21345",
    "CVE-2021-21346",
    "CVE-2021-21347",
    "CVE-2021-21348",
    "CVE-2021-21349",
    "CVE-2021-21350",
    "CVE-2021-21351"
  );
  script_xref(name:"USN", value:"4943-1");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 20.10 / 21.04 : XStream vulnerabilities (USN-4943-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 20.10 / 21.04 host has a package installed that is affected by multiple
vulnerabilities as referenced in the USN-4943-1 advisory.

  - XStream before version 1.4.14 is vulnerable to Remote Code Execution.The vulnerability may allow a remote
    attacker to run arbitrary shell commands only by manipulating the processed input stream. Only users who
    rely on blocklists are affected. Anyone using XStream's Security Framework allowlist is not affected. The
    linked advisory provides code workarounds for users who cannot upgrade. The issue is fixed in version
    1.4.14. (CVE-2020-26217)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.15, a
    Server-Side Forgery Request vulnerability can be activated when unmarshalling. The vulnerability may allow
    a remote attacker to request data from internal resources that are not publicly available only by
    manipulating the processed input stream. If you rely on XStream's default blacklist of the Security
    Framework, you will have to use at least version 1.4.15. The reported vulnerability does not exist if
    running Java 15 or higher. No user is affected who followed the recommendation to setup XStream's Security
    Framework with a whitelist! Anyone relying on XStream's default blacklist can immediately switch to a
    whilelist for the allowed types to avoid the vulnerability. Users of XStream 1.4.14 or below who still
    want to use XStream default blacklist can use a workaround described in more detailed in the referenced
    advisories. (CVE-2020-26258)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.15, is
    vulnerable to an Arbitrary File Deletion on the local host when unmarshalling. The vulnerability may allow
    a remote attacker to delete arbitrary know files on the host as log as the executing process has
    sufficient rights only by manipulating the processed input stream. If you rely on XStream's default
    blacklist of the Security Framework, you will have to use at least version 1.4.15. The reported
    vulnerability does not exist running Java 15 or higher. No user is affected, who followed the
    recommendation to setup XStream's Security Framework with a whitelist! Anyone relying on XStream's default
    blacklist can immediately switch to a whilelist for the allowed types to avoid the vulnerability. Users of
    XStream 1.4.14 or below who still want to use XStream default blacklist can use a workaround described in
    more detailed in the referenced advisories. (CVE-2020-26259)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is vulnerability which may allow a remote attacker to allocate 100% CPU time on the target system
    depending on CPU type or parallel execution of such a payload resulting in a denial of service only by
    manipulating the processed input stream. No user is affected who followed the recommendation to setup
    XStream's security framework with a whitelist limited to the minimal required types. If you rely on
    XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.16.
    (CVE-2021-21341)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability where the processed stream at unmarshalling time contains type information to
    recreate the formerly written objects. XStream creates therefore new instances based on these type
    information. An attacker can manipulate the processed input stream and replace or inject objects, that
    result in a server-side forgery request. No user is affected, who followed the recommendation to setup
    XStream's security framework with a whitelist limited to the minimal required types. If you rely on
    XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.16.
    (CVE-2021-21342)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability where the processed stream at unmarshalling time contains type information to
    recreate the formerly written objects. XStream creates therefore new instances based on these type
    information. An attacker can manipulate the processed input stream and replace or inject objects, that
    result in the deletion of a file on the local host. No user is affected, who followed the recommendation
    to setup XStream's security framework with a whitelist limited to the minimal required types. If you rely
    on XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.16.
    (CVE-2021-21343)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability which may allow a remote attacker to load and execute arbitrary code from a
    remote host only by manipulating the processed input stream. No user is affected, who followed the
    recommendation to setup XStream's security framework with a whitelist limited to the minimal required
    types. If you rely on XStream's default blacklist of the Security Framework, you will have to use at least
    version 1.4.16. (CVE-2021-21344, CVE-2021-21346, CVE-2021-21347)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability which may allow a remote attacker who has sufficient rights to execute commands
    of the host only by manipulating the processed input stream. No user is affected, who followed the
    recommendation to setup XStream's security framework with a whitelist limited to the minimal required
    types. If you rely on XStream's default blacklist of the Security Framework, you will have to use at least
    version 1.4.16. (CVE-2021-21345)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability which may allow a remote attacker to occupy a thread that consumes maximum CPU
    time and will never return. No user is affected, who followed the recommendation to setup XStream's
    security framework with a whitelist limited to the minimal required types. If you rely on XStream's
    default blacklist of the Security Framework, you will have to use at least version 1.4.16.
    (CVE-2021-21348)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability which may allow a remote attacker to request data from internal resources that
    are not publicly available only by manipulating the processed input stream. No user is affected, who
    followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal
    required types. If you rely on XStream's default blacklist of the Security Framework, you will have to use
    at least version 1.4.16. (CVE-2021-21349)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability which may allow a remote attacker to execute arbitrary code only by manipulating
    the processed input stream. No user is affected, who followed the recommendation to setup XStream's
    security framework with a whitelist limited to the minimal required types. If you rely on XStream's
    default blacklist of the Security Framework, you will have to use at least version 1.4.16.
    (CVE-2021-21350)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host
    only by manipulating the processed input stream. No user is affected, who followed the recommendation to
    setup XStream's security framework with a whitelist limited to the minimal required types. If you rely on
    XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.16.
    (CVE-2021-21351)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4943-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected libxstream-java package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26217");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21345");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxstream-java");
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
if (! preg(pattern:"^(18\.04|20\.04|20\.10|21\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 20.10 / 21.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'libxstream-java', 'pkgver': '1.4.11.1-1~18.04.2'},
    {'osver': '20.04', 'pkgname': 'libxstream-java', 'pkgver': '1.4.11.1-1ubuntu0.2'},
    {'osver': '20.10', 'pkgname': 'libxstream-java', 'pkgver': '1.4.11.1-2ubuntu0.1'},
    {'osver': '21.04', 'pkgname': 'libxstream-java', 'pkgver': '1.4.15-1ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libxstream-java');
}