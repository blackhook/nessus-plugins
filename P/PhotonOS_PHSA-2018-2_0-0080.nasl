#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2018-2.0-0080. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(111964);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/07 18:59:51");

  script_cve_id(
    "CVE-2018-7169",
    "CVE-2018-7570",
    "CVE-2018-10360",
    "CVE-2018-10534"
  );

  script_name(english:"Photon OS 2.0: Binutils / File / Linux / Shadow PHSA-2018-2.0-0080 (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of 'binutils', 'file', 'shadow' packages of Photon OS has
been released.");
  # https://github.com/vmware/photon/wiki/Security-Updates-2-80
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56603077");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7169");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:shadow");
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
  "binutils-2.31-1.ph2",
  "binutils-debuginfo-2.31-1.ph2",
  "binutils-devel-2.31-1.ph2",
  "file-5.30-4.ph2",
  "file-debuginfo-5.30-4.ph2",
  "file-devel-5.30-4.ph2",
  "file-libs-5.30-4.ph2",
  "linux-aws-oprofile-4.9.116-1.ph2",
  "linux-oprofile-4.9.116-1.ph2",
  "shadow-4.2.1-16.ph2",
  "shadow-debuginfo-4.2.1-16.ph2",
  "shadow-lang-4.2.1-16.ph2",
  "shadow-tools-4.2.1-16.ph2"
];

foreach (pkg in pkgs)
  if (rpm_check(release:"PhotonOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils / file / linux / shadow");
}
