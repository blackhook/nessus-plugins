#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2017-0045. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(111894);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/07 18:59:50");

  script_cve_id(
    "CVE-2016-9401",
    "CVE-2017-12944",
    "CVE-2017-15041",
    "CVE-2017-15908",
    "CVE-2017-1000099",
    "CVE-2017-1000100",
    "CVE-2017-1000101",
    "CVE-2017-1000254"
  );

  script_name(english:"Photon OS 2.0: Bash / Curl / Go / Libtiff / Systemd PHSA-2017-0045 (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of [go,curl,libtiff,systemd,bash] packages for PhotonOS has
been released.");
  # https://github.com/vmware/photon/wiki/Security-Updates-2-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dc68905");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15041");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:systemd");
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
  "bash-4.4.12-1.ph2",
  "bash-debuginfo-4.4.12-1.ph2",
  "bash-devel-4.4.12-1.ph2",
  "bash-lang-4.4.12-1.ph2",
  "curl-7.54.1-3.ph2",
  "curl-debuginfo-7.54.1-3.ph2",
  "curl-devel-7.54.1-3.ph2",
  "curl-libs-7.54.1-3.ph2",
  "go-1.9.1-1.ph2",
  "go-debuginfo-1.9.1-1.ph2",
  "libtiff-4.0.8-5.ph2",
  "libtiff-debuginfo-4.0.8-5.ph2",
  "libtiff-devel-4.0.8-5.ph2",
  "systemd-233-11.ph2",
  "systemd-debuginfo-233-11.ph2",
  "systemd-devel-233-11.ph2",
  "systemd-lang-233-11.ph2"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bash / curl / go / libtiff / systemd");
}
