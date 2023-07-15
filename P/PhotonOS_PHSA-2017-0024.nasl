#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2017-0024. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(111873);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/07 18:59:50");

  script_cve_id(
    "CVE-2017-6181",
    "CVE-2017-9047",
    "CVE-2017-9048",
    "CVE-2017-9049",
    "CVE-2017-9050",
    "CVE-2017-9287",
    "CVE-2017-10684",
    "CVE-2017-10685"
  );

  script_name(english:"Photon OS 1.0: Libxml2 / Ncurses / Openldap / Ruby PHSA-2017-0024 (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of [ncurses,openldap,libxml2,ruby] packages for PhotonOS has
been released.");
  # https://github.com/vmware/photon/wiki/Security-Updates-54
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e51e1258");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10684");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:ruby");
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
  "libxml2-2.9.4-6.ph1",
  "libxml2-debuginfo-2.9.4-6.ph1",
  "libxml2-devel-2.9.4-6.ph1",
  "libxml2-python-2.9.4-6.ph1",
  "ncurses-6.0-5.ph1",
  "ncurses-compat-6.0-5.ph1",
  "ncurses-debuginfo-6.0-5.ph1",
  "ncurses-devel-6.0-5.ph1",
  "openldap-2.4.43-3.ph1",
  "openldap-debuginfo-2.4.43-3.ph1",
  "ruby-2.4.0-4.ph1",
  "ruby-debuginfo-2.4.0-4.ph1"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / ncurses / openldap / ruby");
}
