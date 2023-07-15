#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2017-0010. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(111859);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/07 18:59:50");

  script_cve_id(
    "CVE-2014-9939",
    "CVE-2015-8933",
    "CVE-2016-4300",
    "CVE-2016-4301",
    "CVE-2016-4302",
    "CVE-2016-4809",
    "CVE-2016-5418",
    "CVE-2016-5844",
    "CVE-2016-6250",
    "CVE-2016-7166",
    "CVE-2016-8687",
    "CVE-2016-8688",
    "CVE-2016-8689",
    "CVE-2017-5601",
    "CVE-2017-6451",
    "CVE-2017-6452",
    "CVE-2017-6455",
    "CVE-2017-6458",
    "CVE-2017-6460",
    "CVE-2017-6462",
    "CVE-2017-6463",
    "CVE-2017-6464",
    "CVE-2017-6969"
  );

  script_name(english:"Photon OS 1.0: Binutils / Libarchive / Ntp PHSA-2017-0010 (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of [binutils,ntp,libarchive] packages for PhotonOS has been
released.");
  # https://github.com/vmware/photon/wiki/Security-Updates-34
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b02cf41");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-9939");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:libarchive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:ntp");
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
  "binutils-2.25.1-4.ph1",
  "binutils-debuginfo-2.25.1-4.ph1",
  "binutils-devel-2.25.1-4.ph1",
  "libarchive-3.3.1-1.ph1",
  "libarchive-debuginfo-3.3.1-1.ph1",
  "libarchive-devel-3.3.1-1.ph1",
  "ntp-4.2.8p10-1.ph1",
  "ntp-debuginfo-4.2.8p10-1.ph1"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils / libarchive / ntp");
}
