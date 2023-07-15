#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2749-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(130194);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-16167");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : sysstat (SUSE-SU-2019:2749-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for sysstat fixes the following issue :

CVE-2019-16167: Fixed a memory corruption due to an integer overflow.
(bsc#1150114)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1150114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-16167/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192749-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb9a46d7"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15-SP1:zypper in
-t patch SUSE-SLE-Module-Server-Applications-15-SP1-2019-2749=1

SUSE Linux Enterprise Module for Server Applications 15:zypper in -t
patch SUSE-SLE-Module-Server-Applications-15-2019-2749=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-2749=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-2749=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sysstat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sysstat-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sysstat-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sysstat-isag");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SLES15", sp:"1", reference:"sysstat-12.0.2-3.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sysstat-debuginfo-12.0.2-3.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sysstat-debugsource-12.0.2-3.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"sysstat-isag-12.0.2-3.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sysstat-12.0.2-3.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sysstat-debuginfo-12.0.2-3.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sysstat-debugsource-12.0.2-3.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"sysstat-isag-12.0.2-3.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sysstat-12.0.2-3.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sysstat-debuginfo-12.0.2-3.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"sysstat-debugsource-12.0.2-3.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sysstat-12.0.2-3.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sysstat-debuginfo-12.0.2-3.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"sysstat-debugsource-12.0.2-3.15.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sysstat");
}
