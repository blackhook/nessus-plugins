#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2021-3.0-0327. The text
# itself is copyright (C) VMware, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155320);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2021-2471",
    "CVE-2021-2478",
    "CVE-2021-2479",
    "CVE-2021-35546",
    "CVE-2021-35591",
    "CVE-2021-35596",
    "CVE-2021-35597",
    "CVE-2021-35610",
    "CVE-2021-35612",
    "CVE-2021-35621",
    "CVE-2021-35622",
    "CVE-2021-35624",
    "CVE-2021-35626",
    "CVE-2021-35627",
    "CVE-2021-35628",
    "CVE-2021-35630",
    "CVE-2021-35631",
    "CVE-2021-35632",
    "CVE-2021-35634",
    "CVE-2021-35635",
    "CVE-2021-35636",
    "CVE-2021-35637",
    "CVE-2021-35638",
    "CVE-2021-35641",
    "CVE-2021-35642",
    "CVE-2021-35643",
    "CVE-2021-35644",
    "CVE-2021-35645",
    "CVE-2021-35646",
    "CVE-2021-35647",
    "CVE-2021-35648"
  );
  script_xref(name:"IAVA", value:"2021-A-0487");

  script_name(english:"Photon OS 3.0: Mysql PHSA-2021-3.0-0327");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the mysql package has been released.

  - Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/J). Supported versions
    that are affected are 8.0.26 and prior. Difficult to exploit vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Connectors. Successful attacks of this
    vulnerability can result in unauthorized access to critical data or complete access to all MySQL
    Connectors accessible data and unauthorized ability to cause a hang or frequently repeatable crash
    (complete DOS) of MySQL Connectors. CVSS 3.1 Base Score 5.9 (Confidentiality and Availability impacts).
    CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:H). (CVE-2021-2471)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 8.0.26 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2478, CVE-2021-2479, CVE-2021-35591)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Replication). Supported
    versions that are affected are 8.0.26 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-35546)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Error Handling). Supported
    versions that are affected are 8.0.26 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-35596)

  - Vulnerability in the MySQL Client product of Oracle MySQL (component: C API). Supported versions that are
    affected are 8.0.26 and prior. Easily exploitable vulnerability allows low privileged attacker with
    network access via multiple protocols to compromise MySQL Client. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
    Client. CVSS 3.1 Base Score 6.5 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-35597)");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Updates-3.0-327.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2471");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-35610");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:3.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/PhotonOS/release", "Host/PhotonOS/rpm-list");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/PhotonOS/release');
if (isnull(release) || release !~ "^VMware Photon") audit(AUDIT_OS_NOT, 'PhotonOS');
if (release !~ "^VMware Photon (?:Linux|OS) 3\.0(\D|$)") audit(AUDIT_OS_NOT, 'PhotonOS 3.0');

if (!get_kb_item('Host/PhotonOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'PhotonOS', cpu);

var flag = 0;

if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'mysql-8.0.27-1.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'mysql-devel-8.0.27-1.ph3')) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mysql');
}
