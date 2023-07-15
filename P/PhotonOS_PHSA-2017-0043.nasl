#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2017-0043. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(111892);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/05 23:25:07");

  script_cve_id(
    "CVE-2017-12188",
    "CVE-2017-15265",
    "CVE-2017-15649",
    "CVE-2017-15951"
  );

  script_name(english:"Photon OS 2.0: Linux PHSA-2017-0043 (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of [linux] packages for PhotonOS has been released.");
  # https://github.com/vmware/photon/wiki/Security-Updates-2-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a9a12a31");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15951");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:linux");
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
  "linux-4.9.60-1.ph2",
  "linux-api-headers-4.9.60-1.ph2",
  "linux-debuginfo-4.9.60-1.ph2",
  "linux-devel-4.9.60-1.ph2",
  "linux-docs-4.9.60-1.ph2",
  "linux-drivers-gpu-4.9.60-1.ph2",
  "linux-esx-4.9.60-1.ph2",
  "linux-esx-debuginfo-4.9.60-1.ph2",
  "linux-esx-devel-4.9.60-1.ph2",
  "linux-esx-docs-4.9.60-1.ph2",
  "linux-oprofile-4.9.60-1.ph2",
  "linux-secure-4.9.60-1.ph2",
  "linux-secure-debuginfo-4.9.60-1.ph2",
  "linux-secure-devel-4.9.60-1.ph2",
  "linux-secure-docs-4.9.60-1.ph2",
  "linux-sound-4.9.60-1.ph2",
  "linux-tools-4.9.60-1.ph2"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux");
}
