##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4892-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(149032);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-2163");
  script_xref(name:"USN", value:"4892-1");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 : OpenJDK vulnerability (USN-4892-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by a
vulnerability as referenced in the USN-4892-1 advisory.

  - Vulnerability in the Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition product of Oracle Java
    SE (component: Libraries). Supported versions that are affected are Java SE: 7u291, 8u281, 11.0.10, 16;
    Java SE Embedded: 8u281; Oracle GraalVM Enterprise Edition: 19.3.5, 20.3.1.2 and 21.0.0.2. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition. Successful attacks require human
    interaction from a person other than the attacker. Successful attacks of this vulnerability can result in
    unauthorized creation, deletion or modification access to critical data or all Java SE, Java SE Embedded,
    Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments
    that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox
    for security. CVSS 3.1 Base Score 5.3 (Integrity impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N). (CVE-2021-2163)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4892-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2163");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-source");
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
    {'osver': '16.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u292-b10-0ubuntu1~16.04.1'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u292-b10-0ubuntu1~16.04.1'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u292-b10-0ubuntu1~16.04.1'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u292-b10-0ubuntu1~16.04.1'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u292-b10-0ubuntu1~16.04.1'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-jamvm', 'pkgver': '8u292-b10-0ubuntu1~16.04.1'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u292-b10-0ubuntu1~16.04.1'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u292-b10-0ubuntu1~16.04.1'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.11+9-0ubuntu2~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.11+9-0ubuntu2~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.11+9-0ubuntu2~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.11+9-0ubuntu2~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.11+9-0ubuntu2~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.11+9-0ubuntu2~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.11+9-0ubuntu2~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u292-b10-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u292-b10-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u292-b10-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u292-b10-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u292-b10-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u292-b10-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u292-b10-0ubuntu1~18.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.11+9-0ubuntu2~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.11+9-0ubuntu2~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.11+9-0ubuntu2~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.11+9-0ubuntu2~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.11+9-0ubuntu2~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.11+9-0ubuntu2~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.11+9-0ubuntu2~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u292-b10-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u292-b10-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u292-b10-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u292-b10-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u292-b10-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u292-b10-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u292-b10-0ubuntu1~20.04'},
    {'osver': '20.10', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.11+9-0ubuntu2~20.10'},
    {'osver': '20.10', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.11+9-0ubuntu2~20.10'},
    {'osver': '20.10', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.11+9-0ubuntu2~20.10'},
    {'osver': '20.10', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.11+9-0ubuntu2~20.10'},
    {'osver': '20.10', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.11+9-0ubuntu2~20.10'},
    {'osver': '20.10', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.11+9-0ubuntu2~20.10'},
    {'osver': '20.10', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.11+9-0ubuntu2~20.10'},
    {'osver': '20.10', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u292-b10-0ubuntu1~20.10'},
    {'osver': '20.10', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u292-b10-0ubuntu1~20.10'},
    {'osver': '20.10', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u292-b10-0ubuntu1~20.10'},
    {'osver': '20.10', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u292-b10-0ubuntu1~20.10'},
    {'osver': '20.10', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u292-b10-0ubuntu1~20.10'},
    {'osver': '20.10', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u292-b10-0ubuntu1~20.10'},
    {'osver': '20.10', 'pkgname': 'openjdk-8-source', 'pkgver': '8u292-b10-0ubuntu1~20.10'}
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
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openjdk-11-demo / openjdk-11-jdk / openjdk-11-jdk-headless / etc');
}