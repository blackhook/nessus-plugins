#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2018-1.0-0178. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(112221);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/07 18:59:50");

  script_cve_id(
    "CVE-2018-1060",
    "CVE-2018-1061",
    "CVE-2018-10811",
    "CVE-2018-10915",
    "CVE-2018-10925"
  );

  script_name(english:"Photon OS 1.0: Postgresql / Python2 / Python3 / Strongswan PHSA-2018-1.0-0178 (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of 'python2', 'strongswan', 'python3', 'postgresql' packages
of Photon OS has been released.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Updates-1.0-178");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1060");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:python2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:strongswan");
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
  "postgresql-9.6.10-1.ph1",
  "postgresql-debuginfo-9.6.10-1.ph1",
  "postgresql-devel-9.6.10-1.ph1",
  "postgresql-libs-9.6.10-1.ph1",
  "python2-2.7.15-1.ph1",
  "python2-debuginfo-2.7.15-1.ph1",
  "python2-devel-2.7.15-1.ph1",
  "python2-libs-2.7.15-1.ph1",
  "python2-tools-2.7.15-1.ph1",
  "python3-3.5.5-2.ph1",
  "python3-debuginfo-3.5.5-2.ph1",
  "python3-devel-3.5.5-2.ph1",
  "python3-libs-3.5.5-2.ph1",
  "python3-tools-3.5.5-2.ph1",
  "strongswan-5.5.2-3.ph1",
  "strongswan-debuginfo-5.5.2-3.ph1"
];

foreach (pkg in pkgs)
  if (rpm_check(release:"PhotonOS-1.0", reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / python2 / python3 / strongswan");
}
