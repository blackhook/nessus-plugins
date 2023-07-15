#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2018-2.0-0037. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(111297);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/05 23:25:07");

  script_cve_id(
    "CVE-2017-12627",
    "CVE-2017-18207",
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
    "CVE-2018-7549",
    "CVE-2018-7643",
    "CVE-2018-7738",
    "CVE-2018-7750",
    "CVE-2018-8740",
    "CVE-2018-1000030",
    "CVE-2018-1000116",
    "CVE-2018-1000117",
    "CVE-2018-1000132"
  );
  script_bugtraq_id(
    102678,
    102681,
    102682,
    102704,
    102706,
    102708,
    102709,
    102710,
    103044,
    103077,
    103219,
    103264,
    103367,
    103466,
    103522,
    103713,
    104527
  );

  script_name(english:"Photon OS 2.0 : Zsh / Python3 / Xerces / Mercurial / Pmd / Pycrypto / Net / Python2 / Util / Mysql / Paramiko / Binutils / Patch / Sqlite (PhotonOS-PHSA-2018-2.0-0037) (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of {'mercurial', 'python2', 'zsh', 'pycrypto', 'patch',
'binutils', 'paramiko', 'httpd', 'mysql', 'xerces-c', 'util-linux',
'net-snmp', 'python3', 'sqlite'} packages of Photon OS has been
released.");
  # https://github.com/vmware/photon/wiki/Security-Updates-2-37
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a24de30");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12627");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:zsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:xerces");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:mercurial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:pmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:pycrypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:net");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:python2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:paramiko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:patch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:2.0");
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
if (release !~ "^VMware Photon (?:Linux|OS) 2\.0(\D|$)") audit(AUDIT_OS_NOT, "PhotonOS 2.0");

if (!get_kb_item("Host/PhotonOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "PhotonOS", cpu);

flag = 0;

pkgs = [
  "binutils-2.30-4.ph2",
  "binutils-debuginfo-2.30-4.ph2",
  "binutils-devel-2.30-4.ph2",
  "mercurial-4.5.3-1.ph2",
  "mercurial-debuginfo-4.5.3-1.ph2",
  "mysql-5.7.21-1.ph2",
  "mysql-debuginfo-5.7.21-1.ph2",
  "mysql-devel-5.7.21-1.ph2",
  "net-snmp-5.7.3-8.ph2",
  "net-snmp-debuginfo-5.7.3-8.ph2",
  "net-snmp-devel-5.7.3-8.ph2",
  "paramiko-2.1.5-1.ph2",
  "patch-2.7.5-5.ph2",
  "patch-debuginfo-2.7.5-5.ph2",
  "pmd-python2-0.0.5-5.ph2",
  "pmd-python3-0.0.5-5.ph2",
  "pycrypto-2.6.1-4.ph2",
  "pycrypto-debuginfo-2.6.1-4.ph2",
  "python2-2.7.13-12.ph2",
  "python2-debuginfo-2.7.13-12.ph2",
  "python2-devel-2.7.13-12.ph2",
  "python2-libs-2.7.13-12.ph2",
  "python2-test-2.7.13-12.ph2",
  "python2-tools-2.7.13-12.ph2",
  "python3-3.6.5-1.ph2",
  "python3-curses-3.6.5-1.ph2",
  "python3-debuginfo-3.6.5-1.ph2",
  "python3-devel-3.6.5-1.ph2",
  "python3-libs-3.6.5-1.ph2",
  "python3-paramiko-2.1.5-1.ph2",
  "python3-paramiko-2.1.5-1.ph2",
  "python3-pip-3.6.5-1.ph2",
  "python3-pycrypto-2.6.1-4.ph2",
  "python3-pycrypto-2.6.1-4.ph2",
  "python3-setuptools-3.6.5-1.ph2",
  "python3-test-3.6.5-1.ph2",
  "python3-tools-3.6.5-1.ph2",
  "python3-xml-3.6.5-1.ph2",
  "sqlite-3.22.0-2.ph2",
  "sqlite-debuginfo-3.22.0-2.ph2",
  "sqlite-devel-3.22.0-2.ph2",
  "sqlite-libs-3.22.0-2.ph2",
  "util-linux-2.32-1.ph2",
  "util-linux-debuginfo-2.32-1.ph2",
  "util-linux-devel-2.32-1.ph2",
  "util-linux-lang-2.32-1.ph2",
  "util-linux-libs-2.32-1.ph2",
  "xerces-c-3.2.1-1.ph2",
  "xerces-c-debuginfo-3.2.1-1.ph2",
  "xerces-c-devel-3.2.1-1.ph2",
  "zsh-5.3.1-6.ph2",
  "zsh-debuginfo-5.3.1-6.ph2",
  "zsh-html-5.3.1-6.ph2"
];

foreach (pkg in pkgs)
  if (rpm_check(release:"PhotonOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "zsh / python3 / xerces / mercurial / pmd / pycrypto / net / python2 / util / mysql / paramiko / binutils / patch / sqlite");
}
