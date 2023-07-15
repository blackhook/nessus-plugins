#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4952-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149446);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2021-2146",
    "CVE-2021-2154",
    "CVE-2021-2162",
    "CVE-2021-2164",
    "CVE-2021-2166",
    "CVE-2021-2169",
    "CVE-2021-2170",
    "CVE-2021-2171",
    "CVE-2021-2172",
    "CVE-2021-2179",
    "CVE-2021-2180",
    "CVE-2021-2193",
    "CVE-2021-2194",
    "CVE-2021-2196",
    "CVE-2021-2201",
    "CVE-2021-2203",
    "CVE-2021-2208",
    "CVE-2021-2212",
    "CVE-2021-2215",
    "CVE-2021-2217",
    "CVE-2021-2226",
    "CVE-2021-2230",
    "CVE-2021-2232",
    "CVE-2021-2278",
    "CVE-2021-2293",
    "CVE-2021-2298",
    "CVE-2021-2299",
    "CVE-2021-2300",
    "CVE-2021-2301",
    "CVE-2021-2304",
    "CVE-2021-2305",
    "CVE-2021-2307",
    "CVE-2021-2308"
  );
  script_xref(name:"USN", value:"4952-1");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 20.10 / 21.04 : MySQL vulnerabilities (USN-4952-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 20.10 / 21.04 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4952-1 advisory.

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Options). Supported versions
    that are affected are 5.7.33 and prior and 8.0.23 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2146)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 5.7.33 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2154)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Audit Plug-in). Supported
    versions that are affected are 5.7.33 and prior and 8.0.23 and prior. Easily exploitable vulnerability
    allows low privileged attacker with network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to
    some of MySQL Server accessible data. CVSS 3.1 Base Score 4.3 (Integrity impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N). (CVE-2021-2162)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.23 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2164, CVE-2021-2170, CVE-2021-2193,
    CVE-2021-2203, CVE-2021-2212, CVE-2021-2230, CVE-2021-2278, CVE-2021-2299)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 5.7.33 and prior and 8.0.23 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2166)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 5.7.33 and prior and 8.0.23 and prior. Easily exploitable vulnerability
    allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2169)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Replication). Supported
    versions that are affected are 5.7.33 and prior and 8.0.23 and prior. Difficult to exploit vulnerability
    allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2171)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 8.0.23 and prior. Easily exploitable vulnerability allows low privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2172)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Group Replication Plugin).
    Supported versions that are affected are 5.7.33 and prior and 8.0.23 and prior. Easily exploitable
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2179)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.33 and prior and 8.0.23 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2180, CVE-2021-2194)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 8.0.23 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2196, CVE-2021-2300, CVE-2021-2305)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Partition). Supported
    versions that are affected are 8.0.23 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2201, CVE-2021-2208)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Stored Procedure). Supported
    versions that are affected are 8.0.23 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2215, CVE-2021-2217, CVE-2021-2293)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Information Schema).
    Supported versions that are affected are 5.7.33 and prior and 8.0.23 and prior. Easily exploitable
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized access to critical data
    or complete access to all MySQL Server accessible data. CVSS 3.1 Base Score 4.9 (Confidentiality impacts).
    CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N). (CVE-2021-2226)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Group Replication Plugin).
    Supported versions that are affected are 8.0.23 and prior. Difficult to exploit vulnerability allows high
    privileged attacker with logon to the infrastructure where MySQL Server executes to compromise MySQL
    Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a partial
    denial of service (partial DOS) of MySQL Server. CVSS 3.1 Base Score 1.9 (Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:L). (CVE-2021-2232)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.23 and prior. Easily exploitable vulnerability allows low privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2298)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Information Schema).
    Supported versions that are affected are 8.0.23 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized read access to a subset of MySQL Server
    accessible data. CVSS 3.1 Base Score 2.7 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N). (CVE-2021-2301, CVE-2021-2308)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Stored Procedure). Supported
    versions that are affected are 8.0.23 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server as well as unauthorized update, insert or delete access to some of MySQL Server
    accessible data. CVSS 3.1 Base Score 5.5 (Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H). (CVE-2021-2304)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Packaging). Supported
    versions that are affected are 5.7.33 and prior and 8.0.23 and prior. Easily exploitable vulnerability
    allows unauthenticated attacker with logon to the infrastructure where MySQL Server executes to compromise
    MySQL Server. Successful attacks require human interaction from a person other than the attacker.
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete
    access to all MySQL Server accessible data as well as unauthorized update, insert or delete access to some
    of MySQL Server accessible data. CVSS 3.1 Base Score 6.1 (Confidentiality and Integrity impacts). CVSS
    Vector: (CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N). (CVE-2021-2307)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4952-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2304");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-2307");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqld-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-core-5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-core-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-router");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-core-5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-core-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-source-5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-source-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-testsuite-5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-testsuite-8.0");
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
    {'osver': '18.04', 'pkgname': 'libmysqlclient-dev', 'pkgver': '5.7.34-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libmysqlclient20', 'pkgver': '5.7.34-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libmysqld-dev', 'pkgver': '5.7.34-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-client', 'pkgver': '5.7.34-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-client-5.7', 'pkgver': '5.7.34-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-client-core-5.7', 'pkgver': '5.7.34-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-server', 'pkgver': '5.7.34-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-server-5.7', 'pkgver': '5.7.34-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-server-core-5.7', 'pkgver': '5.7.34-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-source-5.7', 'pkgver': '5.7.34-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-testsuite', 'pkgver': '5.7.34-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-testsuite-5.7', 'pkgver': '5.7.34-0ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'libmysqlclient-dev', 'pkgver': '8.0.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libmysqlclient21', 'pkgver': '8.0.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-client', 'pkgver': '8.0.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-client-8.0', 'pkgver': '8.0.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-client-core-8.0', 'pkgver': '8.0.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-router', 'pkgver': '8.0.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-server', 'pkgver': '8.0.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-server-8.0', 'pkgver': '8.0.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-server-core-8.0', 'pkgver': '8.0.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-source-8.0', 'pkgver': '8.0.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-testsuite', 'pkgver': '8.0.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-testsuite-8.0', 'pkgver': '8.0.25-0ubuntu0.20.04.1'},
    {'osver': '20.10', 'pkgname': 'libmysqlclient-dev', 'pkgver': '8.0.25-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libmysqlclient21', 'pkgver': '8.0.25-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'mysql-client', 'pkgver': '8.0.25-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'mysql-client-8.0', 'pkgver': '8.0.25-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'mysql-client-core-8.0', 'pkgver': '8.0.25-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'mysql-router', 'pkgver': '8.0.25-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'mysql-server', 'pkgver': '8.0.25-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'mysql-server-8.0', 'pkgver': '8.0.25-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'mysql-server-core-8.0', 'pkgver': '8.0.25-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'mysql-source-8.0', 'pkgver': '8.0.25-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'mysql-testsuite', 'pkgver': '8.0.25-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'mysql-testsuite-8.0', 'pkgver': '8.0.25-0ubuntu0.20.10.1'},
    {'osver': '21.04', 'pkgname': 'libmysqlclient-dev', 'pkgver': '8.0.25-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'libmysqlclient21', 'pkgver': '8.0.25-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'mysql-client', 'pkgver': '8.0.25-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'mysql-client-8.0', 'pkgver': '8.0.25-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'mysql-client-core-8.0', 'pkgver': '8.0.25-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'mysql-router', 'pkgver': '8.0.25-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'mysql-server', 'pkgver': '8.0.25-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'mysql-server-8.0', 'pkgver': '8.0.25-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'mysql-server-core-8.0', 'pkgver': '8.0.25-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'mysql-source-8.0', 'pkgver': '8.0.25-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'mysql-testsuite', 'pkgver': '8.0.25-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'mysql-testsuite-8.0', 'pkgver': '8.0.25-0ubuntu0.21.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmysqlclient-dev / libmysqlclient20 / libmysqlclient21 / etc');
}