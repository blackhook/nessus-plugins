##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4604-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141937);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2019-14775",
    "CVE-2020-14672",
    "CVE-2020-14760",
    "CVE-2020-14765",
    "CVE-2020-14769",
    "CVE-2020-14771",
    "CVE-2020-14773",
    "CVE-2020-14775",
    "CVE-2020-14776",
    "CVE-2020-14777",
    "CVE-2020-14785",
    "CVE-2020-14786",
    "CVE-2020-14789",
    "CVE-2020-14790",
    "CVE-2020-14791",
    "CVE-2020-14793",
    "CVE-2020-14794",
    "CVE-2020-14800",
    "CVE-2020-14804",
    "CVE-2020-14809",
    "CVE-2020-14812",
    "CVE-2020-14814",
    "CVE-2020-14821",
    "CVE-2020-14827",
    "CVE-2020-14828",
    "CVE-2020-14829",
    "CVE-2020-14830",
    "CVE-2020-14836",
    "CVE-2020-14837",
    "CVE-2020-14838",
    "CVE-2020-14839",
    "CVE-2020-14844",
    "CVE-2020-14845",
    "CVE-2020-14846",
    "CVE-2020-14848",
    "CVE-2020-14852",
    "CVE-2020-14853",
    "CVE-2020-14860",
    "CVE-2020-14861",
    "CVE-2020-14866",
    "CVE-2020-14867",
    "CVE-2020-14868",
    "CVE-2020-14869",
    "CVE-2020-14870",
    "CVE-2020-14873",
    "CVE-2020-14878",
    "CVE-2020-14888",
    "CVE-2020-14891",
    "CVE-2020-14893"
  );
  script_xref(name:"USN", value:"4604-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 : MySQL vulnerabilities (USN-4604-1)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4604-1 advisory.

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Stored Procedure). Supported
    versions that are affected are 5.6.49 and prior, 5.7.31 and prior and 8.0.21 and prior. Easily exploitable
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14672)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 5.7.31 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server as well as unauthorized update, insert or delete access to some of MySQL Server
    accessible data. CVSS 3.1 Base Score 5.5 (Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H). (CVE-2020-14760)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: FTS). Supported versions
    that are affected are 5.6.49 and prior, 5.7.31 and prior and 8.0.21 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14765)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 5.6.49 and prior, 5.7.31 and prior and 8.0.21 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14769)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: LDAP Auth).
    Supported versions that are affected are 5.7.31 and prior and 8.0.21 and prior. Difficult to exploit
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a
    partial denial of service (partial DOS) of MySQL Server. CVSS 3.1 Base Score 2.2 (Availability impacts).
    CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:L). (CVE-2020-14771)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14773, CVE-2020-14777, CVE-2020-14785,
    CVE-2020-14794, CVE-2020-14809, CVE-2020-14837, CVE-2020-14839, CVE-2020-14845, CVE-2020-14861,
    CVE-2020-14866, CVE-2020-14868, CVE-2020-14888, CVE-2020-14891, CVE-2020-14893)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.31 and prior and 8.0.21 and prior. Easily exploitable vulnerability allows low privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14775)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.31 and prior and 8.0.21 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14776)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: PS). Supported versions that
    are affected are 8.0.21 and prior. Easily exploitable vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14786, CVE-2020-14844)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: FTS). Supported versions
    that are affected are 5.7.31 and prior and 8.0.21 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14789)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: PS). Supported versions that
    are affected are 5.7.31 and prior and 8.0.21 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14790)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 8.0.21 and prior. Difficult to exploit vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a partial denial of service (partial DOS) of MySQL Server.
    CVSS 3.1 Base Score 2.2 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:L). (CVE-2020-14791)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 5.6.49 and prior, 5.7.31 and prior and 8.0.21 and prior. Easily exploitable
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14793)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Encryption).
    Supported versions that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows low
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14800)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: FTS). Supported versions
    that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14804)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Locking). Supported versions
    that are affected are 5.6.49 and prior, 5.7.31 and prior and 8.0.21 and prior. Easily exploitable
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14812)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14814)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 8.0.21 and prior. Easily exploitable vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14821, CVE-2020-14829, CVE-2020-14848)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: LDAP Auth).
    Supported versions that are affected are 5.7.31 and prior and 8.0.21 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized access to critical data
    or complete access to all MySQL Server accessible data. CVSS 3.1 Base Score 6.5 (Confidentiality impacts).
    CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N). (CVE-2020-14827)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in takeover of MySQL Server. CVSS 3.1 Base Score 7.2 (Confidentiality, Integrity
    and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H). (CVE-2020-14828)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows low privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14830, CVE-2020-14836, CVE-2020-14846)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Privileges).
    Supported versions that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows low
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized read access to a subset of MySQL Server
    accessible data. CVSS 3.1 Base Score 4.3 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N). (CVE-2020-14838)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Charsets). Supported
    versions that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14852)

  - Vulnerability in the MySQL Cluster product of Oracle MySQL (component: Cluster: NDBCluster Plugin).
    Supported versions that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows low
    privileged attacker with network access via multiple protocols to compromise MySQL Cluster. Successful
    attacks require human interaction from a person other than the attacker. Successful attacks of this
    vulnerability can result in unauthorized update, insert or delete access to some of MySQL Cluster
    accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of MySQL
    Cluster. CVSS 3.1 Base Score 4.6 (Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:L). (CVE-2020-14853)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Roles). Supported
    versions that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized update, insert or delete access to some of MySQL Server
    accessible data. CVSS 3.1 Base Score 2.7 (Integrity impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N). (CVE-2020-14860)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DDL). Supported versions
    that are affected are 5.6.49 and prior, 5.7.31 and prior and 8.0.21 and prior. Difficult to exploit
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14867)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: LDAP Auth).
    Supported versions that are affected are 5.7.31 and prior and 8.0.21 and prior. Easily exploitable
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14869)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: X Plugin). Supported
    versions that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14870)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Logging). Supported versions
    that are affected are 8.0.21 and prior. Difficult to exploit vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14873)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: LDAP Auth).
    Supported versions that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows low
    privileged attacker with access to the physical communication segment attached to the hardware where the
    MySQL Server executes to compromise MySQL Server. Successful attacks of this vulnerability can result in
    takeover of MySQL Server. CVSS 3.1 Base Score 8.0 (Confidentiality, Integrity and Availability impacts).
    CVSS Vector: (CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H). (CVE-2020-14878)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4604-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14878");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqld-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-core-5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-core-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-common");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'libmysqlclient-dev', 'pkgver': '5.7.32-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libmysqlclient20', 'pkgver': '5.7.32-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libmysqld-dev', 'pkgver': '5.7.32-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'mysql-client', 'pkgver': '5.7.32-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'mysql-client-5.7', 'pkgver': '5.7.32-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'mysql-client-core-5.7', 'pkgver': '5.7.32-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'mysql-common', 'pkgver': '5.7.32-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'mysql-server', 'pkgver': '5.7.32-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'mysql-server-5.7', 'pkgver': '5.7.32-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'mysql-server-core-5.7', 'pkgver': '5.7.32-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'mysql-source-5.7', 'pkgver': '5.7.32-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'mysql-testsuite', 'pkgver': '5.7.32-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'mysql-testsuite-5.7', 'pkgver': '5.7.32-0ubuntu0.16.04.1'},
    {'osver': '18.04', 'pkgname': 'libmysqlclient-dev', 'pkgver': '5.7.32-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libmysqlclient20', 'pkgver': '5.7.32-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libmysqld-dev', 'pkgver': '5.7.32-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-client', 'pkgver': '5.7.32-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-client-5.7', 'pkgver': '5.7.32-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-client-core-5.7', 'pkgver': '5.7.32-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-server', 'pkgver': '5.7.32-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-server-5.7', 'pkgver': '5.7.32-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-server-core-5.7', 'pkgver': '5.7.32-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-source-5.7', 'pkgver': '5.7.32-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-testsuite', 'pkgver': '5.7.32-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-testsuite-5.7', 'pkgver': '5.7.32-0ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'libmysqlclient-dev', 'pkgver': '8.0.22-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libmysqlclient21', 'pkgver': '8.0.22-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'mysql-client', 'pkgver': '8.0.22-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'mysql-client-8.0', 'pkgver': '8.0.22-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'mysql-client-core-8.0', 'pkgver': '8.0.22-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'mysql-router', 'pkgver': '8.0.22-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'mysql-server', 'pkgver': '8.0.22-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'mysql-server-8.0', 'pkgver': '8.0.22-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'mysql-server-core-8.0', 'pkgver': '8.0.22-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'mysql-source-8.0', 'pkgver': '8.0.22-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'mysql-testsuite', 'pkgver': '8.0.22-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'mysql-testsuite-8.0', 'pkgver': '8.0.22-0ubuntu0.20.04.2'},
    {'osver': '20.10', 'pkgname': 'libmysqlclient-dev', 'pkgver': '8.0.22-0ubuntu0.20.10.2'},
    {'osver': '20.10', 'pkgname': 'libmysqlclient21', 'pkgver': '8.0.22-0ubuntu0.20.10.2'},
    {'osver': '20.10', 'pkgname': 'mysql-client', 'pkgver': '8.0.22-0ubuntu0.20.10.2'},
    {'osver': '20.10', 'pkgname': 'mysql-client-8.0', 'pkgver': '8.0.22-0ubuntu0.20.10.2'},
    {'osver': '20.10', 'pkgname': 'mysql-client-core-8.0', 'pkgver': '8.0.22-0ubuntu0.20.10.2'},
    {'osver': '20.10', 'pkgname': 'mysql-router', 'pkgver': '8.0.22-0ubuntu0.20.10.2'},
    {'osver': '20.10', 'pkgname': 'mysql-server', 'pkgver': '8.0.22-0ubuntu0.20.10.2'},
    {'osver': '20.10', 'pkgname': 'mysql-server-8.0', 'pkgver': '8.0.22-0ubuntu0.20.10.2'},
    {'osver': '20.10', 'pkgname': 'mysql-server-core-8.0', 'pkgver': '8.0.22-0ubuntu0.20.10.2'},
    {'osver': '20.10', 'pkgname': 'mysql-source-8.0', 'pkgver': '8.0.22-0ubuntu0.20.10.2'},
    {'osver': '20.10', 'pkgname': 'mysql-testsuite', 'pkgver': '8.0.22-0ubuntu0.20.10.2'},
    {'osver': '20.10', 'pkgname': 'mysql-testsuite-8.0', 'pkgver': '8.0.22-0ubuntu0.20.10.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmysqlclient-dev / libmysqlclient20 / libmysqlclient21 / etc');
}