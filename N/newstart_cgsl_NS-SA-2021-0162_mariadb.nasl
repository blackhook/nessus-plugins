#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0162. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154603);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-2974",
    "CVE-2020-2574",
    "CVE-2020-2752",
    "CVE-2020-2780",
    "CVE-2020-2812",
    "CVE-2021-2144"
  );
  script_xref(name:"IAVA", value:"2019-A-0383-S");
  script_xref(name:"IAVA", value:"2020-A-0021-S");
  script_xref(name:"IAVA", value:"2020-A-0143");
  script_xref(name:"IAVA", value:"2021-A-0193");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : mariadb Multiple Vulnerabilities (NS-SA-2021-0162)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has mariadb packages installed that are affected
by multiple vulnerabilities:

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 5.6.45 and prior, 5.7.27 and prior and 8.0.17 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score 6.5 (Availability
    impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2019-2974)

  - Vulnerability in the MySQL Client product of Oracle MySQL (component: C API). Supported versions that are
    affected are 5.6.46 and prior, 5.7.28 and prior and 8.0.18 and prior. Difficult to exploit vulnerability
    allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Client.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Client. CVSS 3.0 Base Score 5.9 (Availability impacts). CVSS
    Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-2574)

  - Vulnerability in the MySQL Client product of Oracle MySQL (component: C API). Supported versions that are
    affected are 5.6.47 and prior, 5.7.27 and prior and 8.0.17 and prior. Difficult to exploit vulnerability
    allows low privileged attacker with network access via multiple protocols to compromise MySQL Client.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Client. CVSS 3.0 Base Score 5.3 (Availability impacts). CVSS
    Vector: (CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-2752)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 5.6.47 and prior, 5.7.29 and prior and 8.0.19 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score 6.5 (Availability
    impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-2780)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Stored Procedure). Supported
    versions that are affected are 5.6.47 and prior, 5.7.29 and prior and 8.0.19 and prior. Easily exploitable
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score 4.9 (Availability
    impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-2812)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Parser). Supported versions
    that are affected are 5.7.29 and prior and 8.0.19 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in takeover of MySQL Server. CVSS 3.1 Base Score 7.2
    (Confidentiality, Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H). (CVE-2021-2144)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0162");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-2974");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-2574");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-2752");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-2780");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-2812");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-2144");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL mariadb packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2144");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:mariadb-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:mariadb-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:mariadb-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:mariadb-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:mariadb-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:mariadb-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'mariadb-5.5.68-1.el7',
    'mariadb-bench-5.5.68-1.el7',
    'mariadb-devel-5.5.68-1.el7',
    'mariadb-embedded-5.5.68-1.el7',
    'mariadb-embedded-devel-5.5.68-1.el7',
    'mariadb-libs-5.5.68-1.el7',
    'mariadb-server-5.5.68-1.el7',
    'mariadb-test-5.5.68-1.el7'
  ],
  'CGSL MAIN 5.05': [
    'mariadb-5.5.68-1.el7',
    'mariadb-bench-5.5.68-1.el7',
    'mariadb-devel-5.5.68-1.el7',
    'mariadb-embedded-5.5.68-1.el7',
    'mariadb-embedded-devel-5.5.68-1.el7',
    'mariadb-libs-5.5.68-1.el7',
    'mariadb-server-5.5.68-1.el7',
    'mariadb-test-5.5.68-1.el7'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mariadb');
}
