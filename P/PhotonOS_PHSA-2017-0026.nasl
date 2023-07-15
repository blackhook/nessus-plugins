#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2017-0026. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(111875);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/07 18:59:50");

  script_cve_id(
    "CVE-2013-7459",
    "CVE-2017-10053",
    "CVE-2017-10067",
    "CVE-2017-10074",
    "CVE-2017-10078",
    "CVE-2017-10086",
    "CVE-2017-10087",
    "CVE-2017-10089",
    "CVE-2017-10090",
    "CVE-2017-10096",
    "CVE-2017-10102",
    "CVE-2017-10104",
    "CVE-2017-10105",
    "CVE-2017-10107",
    "CVE-2017-10108",
    "CVE-2017-10109",
    "CVE-2017-10111",
    "CVE-2017-10114",
    "CVE-2017-10115",
    "CVE-2017-10116",
    "CVE-2017-10117",
    "CVE-2017-10118",
    "CVE-2017-10121",
    "CVE-2017-10125",
    "CVE-2017-10135",
    "CVE-2017-10145",
    "CVE-2017-10176",
    "CVE-2017-10198",
    "CVE-2017-10243"
  );

  script_name(english:"Photon OS 1.0: Openjdk / Openjre / Pycrypto / Python3 PHSA-2017-0026 (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of [openjdk,openjre,pycrypto,python3-pycrypto] packages for
PhotonOS has been released.");
  # https://github.com/vmware/photon/wiki/Security-Updates-56
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?63d4d4e0");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-7459");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:openjre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:pycrypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:python3");
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
  "openjdk-1.8.0.141-1.ph1",
  "openjdk-debuginfo-1.8.0.141-1.ph1",
  "openjdk-doc-1.8.0.141-1.ph1",
  "openjdk-sample-1.8.0.141-1.ph1",
  "openjdk-src-1.8.0.141-1.ph1",
  "openjre-1.8.0.141-1.ph1",
  "pycrypto-2.6.1-3.ph1",
  "pycrypto-debuginfo-2.6.1-3.ph1",
  "python3-pycrypto-2.6.1-3.ph1"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openjdk / openjre / pycrypto / python3");
}
