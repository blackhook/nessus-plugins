#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0017-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(132703);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-18388", "CVE-2019-18389", "CVE-2019-18390", "CVE-2019-18391");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : virglrenderer (SUSE-SU-2020:0017-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for virglrenderer fixes the following issues :

CVE-2019-18388: Fixed a NULL pointer dereference which could have led
to denial of service (bsc#1159479).

CVE-2019-18390: Fixed an out of bound read which could have led to
denial of service (bsc#1159478).

CVE-2019-18389: Fixed a heap buffer overflow which could have led to
guest escape or denial of service (bsc#1159482).

CVE-2019-18391: Fixed a heap-based buffer overflow which could have
led to guest escape or denial of service (bsc#1159486).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1159478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1159479"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1159482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1159486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-18388/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-18389/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-18390/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-18391/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200017-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef799c81"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15-SP1:zypper in
-t patch SUSE-SLE-Module-Server-Applications-15-SP1-2020-17=1

SUSE Linux Enterprise Module for Server Applications 15:zypper in -t
patch SUSE-SLE-Module-Server-Applications-15-2020-17=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-17=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2020-17=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirglrenderer0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirglrenderer0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:virglrenderer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:virglrenderer-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:virglrenderer-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:virglrenderer-test-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:virglrenderer-test-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

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
if (rpm_check(release:"SLES15", sp:"1", reference:"libvirglrenderer0-0.6.0-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libvirglrenderer0-debuginfo-0.6.0-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"virglrenderer-debuginfo-0.6.0-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"virglrenderer-debugsource-0.6.0-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"virglrenderer-devel-0.6.0-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"virglrenderer-test-server-0.6.0-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"virglrenderer-test-server-debuginfo-0.6.0-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirglrenderer0-0.6.0-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvirglrenderer0-debuginfo-0.6.0-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"virglrenderer-debuginfo-0.6.0-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"virglrenderer-debugsource-0.6.0-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"virglrenderer-devel-0.6.0-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"virglrenderer-test-server-0.6.0-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"virglrenderer-test-server-debuginfo-0.6.0-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"virglrenderer-debuginfo-0.6.0-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"virglrenderer-debugsource-0.6.0-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"virglrenderer-test-server-0.6.0-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"virglrenderer-test-server-debuginfo-0.6.0-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"virglrenderer-debuginfo-0.6.0-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"virglrenderer-debugsource-0.6.0-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"virglrenderer-test-server-0.6.0-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"virglrenderer-test-server-debuginfo-0.6.0-4.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "virglrenderer");
}