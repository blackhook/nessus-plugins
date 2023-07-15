#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2018-2.0-0084. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(112035);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/19");

  script_cve_id(
    "CVE-2018-0732",
    "CVE-2018-1122",
    "CVE-2018-1123",
    "CVE-2018-1124",
    "CVE-2018-1125",
    "CVE-2018-1126",
    "CVE-2018-12015"
  );
  script_bugtraq_id(104214, 104423, 104442);
  script_xref(name:"IAVA", value:"2018-A-0407-S");

  script_name(english:"Photon OS 2.0: Openssl / Procps-ng / Perl PHSA-2018-2.0-0084 (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of 'procps-ng', 'openssl', 'perl' packages of Photon OS has
been released.");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1126");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  # https://github.com/vmware/photon/wiki/Security-Updates-2-85
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1045f155");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:procps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:2.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  "openssl-1.0.2o-3.ph2",
  "openssl-debuginfo-1.0.2o-3.ph2",
  "openssl-devel-1.0.2o-3.ph2",
  "openssl-perl-1.0.2o-3.ph2",
  "perl-5.24.1-6.ph2",
  "perl-apparmor-2.13-3.ph2",
  "perl-debuginfo-5.24.1-6.ph2",
  "procps-ng-3.3.15-1.ph2",
  "procps-ng-debuginfo-3.3.15-1.ph2",
  "procps-ng-devel-3.3.15-1.ph2",
  "procps-ng-lang-3.3.15-1.ph2"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / procps-ng / perl");
}
