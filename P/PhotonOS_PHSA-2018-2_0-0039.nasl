#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2018-2.0-0039. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(111298);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/07 18:59:50");

  script_cve_id(
    "CVE-2017-11613",
    "CVE-2018-1064",
    "CVE-2018-1083",
    "CVE-2018-1303",
    "CVE-2018-2794",
    "CVE-2018-2795",
    "CVE-2018-2796",
    "CVE-2018-2797",
    "CVE-2018-2798",
    "CVE-2018-2799",
    "CVE-2018-2811",
    "CVE-2018-2814",
    "CVE-2018-2815",
    "CVE-2018-2825",
    "CVE-2018-2826",
    "CVE-2018-5784",
    "CVE-2018-1000140"
  );
  script_bugtraq_id(
    99977,
    103522,
    103572,
    103782,
    103796,
    103798,
    103810,
    103817,
    103841,
    103846,
    103847,
    103848,
    103868,
    103872,
    104510
  );
  script_name(english:"Photon OS 2.0 : openjdk8 / httpd / librelp / zsh / libvirt (PhotonOS-PHSA-2018-2.0-0039) (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of {'openjdk8', 'httpd', 'librelp', 'zsh', 'libvirt',
'libtiff'} packages of Photon OS has been released.");
  # https://github.com/vmware/photon/wiki/Security-Updates-2-39
    script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17165379");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000140");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:zsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:librelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:openjdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:libtiff");
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
  "httpd-2.4.33-1.ph2",
  "httpd-debuginfo-2.4.33-1.ph2",
  "httpd-devel-2.4.33-1.ph2",
  "httpd-docs-2.4.33-1.ph2",
  "httpd-tools-2.4.33-1.ph2",
  "librelp-1.2.13-2.ph2",
  "librelp-debuginfo-1.2.13-2.ph2",
  "librelp-devel-1.2.13-2.ph2",
  "libtiff-4.0.9-4.ph2",
  "libtiff-debuginfo-4.0.9-4.ph2",
  "libtiff-devel-4.0.9-4.ph2",
  "libvirt-3.2.0-5.ph2",
  "libvirt-debuginfo-3.2.0-5.ph2",
  "libvirt-devel-3.2.0-5.ph2",
  "libvirt-docs-3.2.0-5.ph2",
  "openjdk8-1.8.0.172-1.ph2",
  "openjdk8-debuginfo-1.8.0.172-1.ph2",
  "openjdk8-doc-1.8.0.172-1.ph2",
  "openjdk8-sample-1.8.0.172-1.ph2",
  "openjdk8-src-1.8.0.172-1.ph2",
  "zsh-5.3.1-7.ph2",
  "zsh-debuginfo-5.3.1-7.ph2",
  "zsh-html-5.3.1-7.ph2"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "zsh / httpd / librelp / openjdk8 / libvirt / libtiff");
}
