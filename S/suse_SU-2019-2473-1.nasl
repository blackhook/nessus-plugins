#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2473-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(129401);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-9511", "CVE-2019-9513");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : nghttp2 (SUSE-SU-2019:2473-1) (Data Dribble) (Resource Loop)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for nghttp2 fixes the following issues :

Security issues fixed :

CVE-2019-9513: Fixed HTTP/2 implementation that is vulnerable to
resource loops, potentially leading to a denial of service
(bsc#1146184).

CVE-2019-9511: Fixed HTTP/2 implementations that are vulnerable to
window size manipulation and stream prioritization manipulation,
potentially leading to a denial of service (bsc#11461).

Bug fixes and enhancements: Fixed mistake in spec file (bsc#1125689)

Fixed build issue with boost 1.70.0 (bsc#1134616)

Feature: Add W&S module (FATE#326776, bsc#1112438)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1112438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1125689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1134616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146182");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146184");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9511/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9513/");
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192473-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?487ca1de");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-2473=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-2473=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-2473=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-2473=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnghttp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnghttp2-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnghttp2-14-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnghttp2-14-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnghttp2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnghttp2_asio-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnghttp2_asio1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnghttp2_asio1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnghttp2_asio1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nghttp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nghttp2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nghttp2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-nghttp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-nghttp2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libnghttp2-14-32bit-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libnghttp2-14-32bit-debuginfo-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libnghttp2_asio1-32bit-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libnghttp2_asio1-32bit-debuginfo-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libnghttp2-14-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libnghttp2-14-debuginfo-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libnghttp2-devel-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libnghttp2_asio-devel-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libnghttp2_asio1-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libnghttp2_asio1-debuginfo-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"nghttp2-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"nghttp2-debuginfo-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"nghttp2-debugsource-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-nghttp2-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-nghttp2-debuginfo-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libnghttp2-14-32bit-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libnghttp2-14-32bit-debuginfo-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnghttp2-14-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnghttp2-14-debuginfo-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnghttp2-devel-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnghttp2_asio-devel-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnghttp2_asio1-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnghttp2_asio1-debuginfo-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nghttp2-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nghttp2-debuginfo-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nghttp2-debugsource-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-nghttp2-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-nghttp2-debuginfo-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libnghttp2-14-32bit-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libnghttp2-14-32bit-debuginfo-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libnghttp2_asio1-32bit-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libnghttp2_asio1-32bit-debuginfo-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libnghttp2-14-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libnghttp2-14-debuginfo-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libnghttp2-devel-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libnghttp2_asio-devel-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libnghttp2_asio1-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libnghttp2_asio1-debuginfo-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"nghttp2-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"nghttp2-debuginfo-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"nghttp2-debugsource-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-nghttp2-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-nghttp2-debuginfo-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libnghttp2-14-32bit-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libnghttp2-14-32bit-debuginfo-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnghttp2-14-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnghttp2-14-debuginfo-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnghttp2-devel-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnghttp2_asio-devel-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnghttp2_asio1-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnghttp2_asio1-debuginfo-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nghttp2-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nghttp2-debuginfo-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nghttp2-debugsource-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-nghttp2-1.39.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-nghttp2-debuginfo-1.39.2-3.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nghttp2");
}
