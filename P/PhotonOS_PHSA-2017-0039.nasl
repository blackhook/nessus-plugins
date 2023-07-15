#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2017-0039. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(111888);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/07 18:59:50");

  script_cve_id(
    "CVE-2017-5969",
    "CVE-2017-8932",
    "CVE-2017-9263",
    "CVE-2017-9814"
  );

  script_name(english:"Photon OS 1.0: Cairo / Go / Libxml2 / Openvswitch PHSA-2017-0039 (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of [cairo,openvswitch,libxml2,go] packages for PhotonOS has
been released.");
  # https://github.com/vmware/photon/wiki/Security-Updates-79
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?896db741");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9814");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:cairo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:openvswitch");
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
  "cairo-1.14.8-2.ph1",
  "cairo-debuginfo-1.14.8-2.ph1",
  "cairo-devel-1.14.8-2.ph1",
  "go-1.8.1-2.ph1",
  "go-debuginfo-1.8.1-2.ph1",
  "libxml2-2.9.6-1.ph1",
  "libxml2-debuginfo-2.9.6-1.ph1",
  "libxml2-devel-2.9.6-1.ph1",
  "libxml2-python-2.9.6-1.ph1",
  "openvswitch-2.6.1-4.ph1",
  "openvswitch-debuginfo-2.6.1-4.ph1",
  "openvswitch-devel-2.6.1-4.ph1",
  "openvswitch-doc-2.6.1-4.ph1"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cairo / go / libxml2 / openvswitch");
}
