#
# (C) Tenable Network Security, Inc.`
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2018-1.0-0104. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(121805);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/02 21:54:17");

  script_cve_id(
    "CVE-2017-13716",
    "CVE-2017-14930",
    "CVE-2017-14932",
    "CVE-2017-14933",
    "CVE-2017-14934",
    "CVE-2017-14938",
    "CVE-2017-14939",
    "CVE-2017-14940",
    "CVE-2017-14974",
    "CVE-2017-15021",
    "CVE-2017-15022",
    "CVE-2017-15023",
    "CVE-2017-15024",
    "CVE-2017-15025",
    "CVE-2017-17080",
    "CVE-2017-17123"
  );

  script_name(english:"Photon OS 1.0: Binutils PHSA-2018-1.0-0104");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the binutils package has been released.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Updates-1.0-104.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-13716");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:binutils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:1.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/PhotonOS/release", "Host/PhotonOS/rpm-list");

  exit(0);
}

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

if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-debuginfo-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-debuginfo-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-debuginfo-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-debuginfo-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-debuginfo-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-debuginfo-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-debuginfo-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-debuginfo-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-debuginfo-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-debuginfo-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-debuginfo-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-debuginfo-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-debuginfo-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-debuginfo-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-debuginfo-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-debuginfo-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-devel-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-devel-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-devel-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-devel-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-devel-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-devel-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-devel-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-devel-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-devel-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-devel-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-devel-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-devel-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-devel-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-devel-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-devel-2.30-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"binutils-devel-2.30-1.ph1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils");
}
