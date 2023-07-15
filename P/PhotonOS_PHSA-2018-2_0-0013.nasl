#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2018-2.0-0013. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(111283);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/07 18:59:50");

  script_cve_id(
    "CVE-2017-9937",
    "CVE-2017-17790",
    "CVE-2017-17973",
    "CVE-2017-18013",
    "CVE-2018-2581",
    "CVE-2018-2582",
    "CVE-2018-2588",
    "CVE-2018-2599",
    "CVE-2018-2602",
    "CVE-2018-2603",
    "CVE-2018-2618",
    "CVE-2018-2627",
    "CVE-2018-2629",
    "CVE-2018-2633",
    "CVE-2018-2634",
    "CVE-2018-2637",
    "CVE-2018-2638",
    "CVE-2018-2639",
    "CVE-2018-2641",
    "CVE-2018-2663",
    "CVE-2018-2677",
    "CVE-2018-2678"
  );
  script_bugtraq_id(
    99304,
    102286,
    102331,
    102345,
    102546,
    102556,
    102557,
    102576,
    102584,
    102592,
    102597,
    102605,
    102612,
    102615,
    102625,
    102633,
    102636,
    102642,
    102656,
    102659,
    102661,
    102662
  );

  script_name(english:"Photon OS 2.0 : libtiff / openjdk8 / ruby (PhotonOS-PHSA-2018-2.0-0013) (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of {'libtiff', 'openjdk8', 'ruby'} packages of Photon OS has
been released.");
  # https://github.com/vmware/photon/wiki/Security-Updates-2-13
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?49126eda");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-17790");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:openjdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:ruby");
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
  "libtiff-4.0.9-1.ph2",
  "libtiff-debuginfo-4.0.9-1.ph2",
  "libtiff-devel-4.0.9-1.ph2",
  "openjdk8-1.8.0.162-1.ph2",
  "openjdk8-debuginfo-1.8.0.162-1.ph2",
  "openjdk8-doc-1.8.0.162-1.ph2",
  "openjdk8-sample-1.8.0.162-1.ph2",
  "openjdk8-src-1.8.0.162-1.ph2",
  "ruby-2.4.3-2.ph2",
  "ruby-debuginfo-2.4.3-2.ph2"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openjdk8 / libtiff / ruby");
}
