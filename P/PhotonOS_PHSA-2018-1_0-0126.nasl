#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2018-1.0-0126. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(111930);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/05 23:25:07");

  script_cve_id(
    "CVE-2017-9022",
    "CVE-2017-9023",
    "CVE-2017-12627",
    "CVE-2017-15710",
    "CVE-2017-15715",
    "CVE-2017-18207",
    "CVE-2018-1301",
    "CVE-2018-1302",
    "CVE-2018-1303",
    "CVE-2018-2573",
    "CVE-2018-2583",
    "CVE-2018-2612",
    "CVE-2018-2622",
    "CVE-2018-2640",
    "CVE-2018-2665",
    "CVE-2018-2668",
    "CVE-2018-2703",
    "CVE-2018-6594",
    "CVE-2018-6951",
    "CVE-2018-7208",
    "CVE-2018-7643",
    "CVE-2018-7750",
    "CVE-2018-8740",
    "CVE-2018-1000116",
    "CVE-2018-1000117",
    "CVE-2018-1000132"
  );

  script_name(english:"Photon OS 1.0: Binutils / Httpd / Mercurial / Mysql / Net / Paramiko / Patch / Pycrypto / Python3 / Sqlite / Strongswan / Xerces PHSA-2018-1.0-0126 (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of 'paramiko', 'mysql', 'mercurial', 'binutils', 'pycrypto',
'patch', 'sqlite-autoconf', 'httpd', 'python3', 'xerces-c',
'strongswan', 'net-snmp' packages of Photon OS has been released.");
  # https://github.com/vmware/photon/wiki/Security-Updates-1.0-126
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22ce6999");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12627");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:mercurial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:net");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:paramiko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:patch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:pycrypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:strongswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:xerces");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:1.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/PhotonOS/release", "Host/PhotonOS/rpm-list");

  exit(0);
}

exit(0, "This plugin has been deprecated.");

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/PhotonOS/release");
if (isnull(release) || release !~ "^VMware Photon") audit(AUDIT_OS_NOT, "PhotonOS");
if (release !~ "^VMware Photon (?:Linux|OS) 1\.0(\D|$)") audit(AUDIT_OS_NOT, "PhotonOS 1.0");

if (!get_kb_item("Host/PhotonOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "PhotonOS", cpu);

flag = 0;

pkgs = [
  "binutils-2.30-3.ph1",
  "binutils-debuginfo-2.30-3.ph1",
  "binutils-devel-2.30-3.ph1",
  "httpd-2.4.33-1.ph1",
  "httpd-debuginfo-2.4.33-1.ph1",
  "httpd-devel-2.4.33-1.ph1",
  "httpd-docs-2.4.33-1.ph1",
  "httpd-tools-2.4.33-1.ph1",
  "mercurial-4.5.3-1.ph1",
  "mercurial-debuginfo-4.5.3-1.ph1",
  "mysql-5.7.21-1.ph1",
  "mysql-debuginfo-5.7.21-1.ph1",
  "mysql-devel-5.7.21-1.ph1",
  "net-snmp-5.7.3-5.ph1",
  "net-snmp-debuginfo-5.7.3-5.ph1",
  "net-snmp-devel-5.7.3-5.ph1",
  "paramiko-1.17.6-1.ph1",
  "patch-2.7.5-3.ph1",
  "patch-debuginfo-2.7.5-3.ph1",
  "pycrypto-2.6.1-5.ph1",
  "pycrypto-debuginfo-2.6.1-5.ph1",
  "python3-3.5.4-2.ph1",
  "python3-debuginfo-3.5.4-2.ph1",
  "python3-devel-3.5.4-2.ph1",
  "python3-libs-3.5.4-2.ph1",
  "python3-paramiko-1.17.6-1.ph1",
  "python3-pycrypto-2.6.1-5.ph1",
  "python3-tools-3.5.4-2.ph1",
  "sqlite-autoconf-3.22.0-2.ph1",
  "sqlite-autoconf-debuginfo-3.22.0-2.ph1",
  "strongswan-5.5.2-1.ph1",
  "strongswan-debuginfo-5.5.2-1.ph1",
  "xerces-c-3.2.1-1.ph1",
  "xerces-c-debuginfo-3.2.1-1.ph1",
  "xerces-c-devel-3.2.1-1.ph1"
];

foreach (pkg in pkgs)
  if (rpm_check(release:"PhotonOS-1.0", reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils / httpd / mercurial / mysql / net / paramiko / patch / pycrypto / python3 / sqlite / strongswan / xerces");
}
