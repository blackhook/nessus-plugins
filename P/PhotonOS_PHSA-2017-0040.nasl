#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2017-0040. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(111889);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/05 23:25:07");

  script_cve_id(
    "CVE-2013-4420",
    "CVE-2014-9844",
    "CVE-2014-9913",
    "CVE-2016-0634",
    "CVE-2016-9844",
    "CVE-2017-9526",
    "CVE-2017-10274",
    "CVE-2017-10285",
    "CVE-2017-10309",
    "CVE-2017-10346",
    "CVE-2017-10388",
    "CVE-2017-11185",
    "CVE-2017-12133"
  );

  script_name(english:"Photon OS 1.0: Bash / Glibc / Libgcrypt / Libtar / Openjdk / Openjre / Strongswan / Unzip PHSA-2017-0040 (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of
[openjdk,openjre,bash,libtar,glibc,libgcrypt,strongswan,unzip]
packages for PhotonOS has been released.");
  # https://github.com/vmware/photon/wiki/Security-Updates-80
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0fdbe24");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10285");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:libgcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:libtar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:openjre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:strongswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:unzip");
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
  "bash-4.3.48-1.ph1",
  "bash-debuginfo-4.3.48-1.ph1",
  "bash-lang-4.3.48-1.ph1",
  "glibc-2.22-14.ph1",
  "glibc-devel-2.22-14.ph1",
  "glibc-lang-2.22-14.ph1",
  "libgcrypt-1.7.6-3.ph1",
  "libgcrypt-debuginfo-1.7.6-3.ph1",
  "libgcrypt-devel-1.7.6-3.ph1",
  "libtar-1.2.20-3.ph1",
  "libtar-devel-1.2.20-3.ph1",
  "openjdk-1.8.0.151-1.ph1",
  "openjdk-debuginfo-1.8.0.151-1.ph1",
  "openjdk-doc-1.8.0.151-1.ph1",
  "openjdk-sample-1.8.0.151-1.ph1",
  "openjdk-src-1.8.0.151-1.ph1",
  "openjre-1.8.0.151-1.ph1",
  "strongswan-5.5.1-2.ph1",
  "strongswan-debuginfo-5.5.1-2.ph1",
  "unzip-6.0-8.ph1"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bash / glibc / libgcrypt / libtar / openjdk / openjre / strongswan / unzip");
}
