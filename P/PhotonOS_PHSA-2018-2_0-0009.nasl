#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2018-2.0-0009. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(111278);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/05 23:25:07");

  script_cve_id(
    "CVE-2017-8818",
    "CVE-2017-8824",
    "CVE-2017-17426",
    "CVE-2017-17433",
    "CVE-2017-17434",
    "CVE-2017-17448",
    "CVE-2017-17450"
  );
  script_bugtraq_id(
    102014,
    102056,
    102110,
    102117
  );

  script_name(english:"Photon OS 2.0 : glibc / linux / rsync / curl (PhotonOS-PHSA-2018-2.0-0009) (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of {'glibc', 'linux', 'rsync', 'curl'} packages of Photon OS
has been released.");
  # https://github.com/vmware/photon/wiki/Security-Updates-2-9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a15d8a6");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8818");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:rsync");
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
  "curl-7.56.1-2.ph2",
  "curl-debuginfo-7.56.1-2.ph2",
  "curl-devel-7.56.1-2.ph2",
  "curl-libs-7.56.1-2.ph2",
  "glibc-2.26-7.ph2",
  "glibc-debuginfo-2.26-7.ph2",
  "glibc-devel-2.26-7.ph2",
  "glibc-i18n-2.26-7.ph2",
  "glibc-iconv-2.26-7.ph2",
  "glibc-lang-2.26-7.ph2",
  "glibc-nscd-2.26-7.ph2",
  "glibc-tools-2.26-7.ph2",
  "linux-4.9.74-1.ph2",
  "linux-api-headers-4.9.74-1.ph2",
  "linux-debuginfo-4.9.74-1.ph2",
  "linux-devel-4.9.74-1.ph2",
  "linux-docs-4.9.74-1.ph2",
  "linux-drivers-gpu-4.9.74-1.ph2",
  "linux-esx-4.9.74-1.ph2",
  "linux-esx-debuginfo-4.9.74-1.ph2",
  "linux-esx-devel-4.9.74-1.ph2",
  "linux-esx-docs-4.9.74-1.ph2",
  "linux-oprofile-4.9.74-1.ph2",
  "linux-secure-4.9.74-1.ph2",
  "linux-secure-debuginfo-4.9.74-1.ph2",
  "linux-secure-devel-4.9.74-1.ph2",
  "linux-secure-docs-4.9.74-1.ph2",
  "linux-secure-lkcm-4.9.74-1.ph2",
  "linux-sound-4.9.74-1.ph2",
  "linux-tools-4.9.74-1.ph2",
  "rsync-3.1.2-5.ph2",
  "rsync-debuginfo-3.1.2-5.ph2"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / linux / glibc / rsync");
}
