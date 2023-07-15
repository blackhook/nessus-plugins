#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2017-1.0-0095. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(111904);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/07 18:59:50");

  script_cve_id(
    "CVE-2017-7501",
    "CVE-2017-8818",
    "CVE-2017-12190",
    "CVE-2017-14992",
    "CVE-2017-17121",
    "CVE-2017-17122",
    "CVE-2017-17124",
    "CVE-2017-17125",
    "CVE-2017-1000407"
  );

  script_name(english:"Photon OS 1.0: Binutils / Curl / Docker / Linux / Rpm PHSA-2017-1.0-0095 (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of 'curl', 'docker', 'binutils', 'linux','rpm' packages of
Photon OS has been released.");
  # https://github.com/vmware/photon/wiki/Security-Updates-1.0-95
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e92d3f9");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8818");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:rpm");
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
  "binutils-2.29.1-3.ph1",
  "binutils-debuginfo-2.29.1-3.ph1",
  "binutils-devel-2.29.1-3.ph1",
  "curl-7.56.1-2.ph1",
  "curl-debuginfo-7.56.1-2.ph1",
  "docker-17.06.0-2.ph1",
  "docker-doc-17.06.0-2.ph1",
  "linux-4.4.106-1.ph1",
  "linux-api-headers-4.4.106-1.ph1",
  "linux-debuginfo-4.4.106-1.ph1",
  "linux-dev-4.4.106-1.ph1",
  "linux-docs-4.4.106-1.ph1",
  "linux-drivers-gpu-4.4.106-1.ph1",
  "linux-esx-4.4.106-1.ph1",
  "linux-esx-debuginfo-4.4.106-1.ph1",
  "linux-esx-devel-4.4.106-1.ph1",
  "linux-esx-docs-4.4.106-1.ph1",
  "linux-oprofile-4.4.106-1.ph1",
  "linux-sound-4.4.106-1.ph1",
  "linux-tools-4.4.106-1.ph1",
  "rpm-4.13.0.1-4.ph1",
  "rpm-debuginfo-4.13.0.1-4.ph1"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils / curl / docker / linux / rpm");
}
