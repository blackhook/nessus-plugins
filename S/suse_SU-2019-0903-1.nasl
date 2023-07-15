#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0903-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(123928);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2016-10739");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : glibc (SUSE-SU-2019:0903-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for glibc fixes the following issues :

Security issue fixed :

CVE-2016-10739: Fixed an improper implementation of getaddrinfo
function which could allow applications to incorrectly assume that had
parsed a valid string, without the possibility of embedded HTTP
headers or other potentially dangerous substrings (bsc#1122729).

Other issue fixed: Fixed an issue where pthread_mutex_trylock did not
use a correct order of instructions while maintained the robust mutex
list due to missing compiler barriers (bsc#1130045).

Added new Japanese Era name support (bsc#1100396).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1100396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1122729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1130045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10739/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190903-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca44d61d"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-903=1

SUSE Linux Enterprise Module for Development Tools 15:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-2019-903=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-903=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-devel-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-locale-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-locale-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-utils-src-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nscd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/09");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"glibc-32bit-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"glibc-32bit-debuginfo-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"glibc-devel-32bit-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"glibc-devel-32bit-debuginfo-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-debuginfo-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-debugsource-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-devel-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-devel-debuginfo-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-devel-static-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-extra-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-extra-debuginfo-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-locale-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-locale-base-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-locale-base-debuginfo-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-profile-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-utils-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-utils-debuginfo-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-utils-src-debugsource-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nscd-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nscd-debuginfo-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"glibc-32bit-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"glibc-32bit-debuginfo-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"glibc-devel-32bit-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"glibc-devel-32bit-debuginfo-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-debuginfo-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-debugsource-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-devel-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-devel-debuginfo-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-devel-static-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-extra-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-extra-debuginfo-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-locale-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-locale-base-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-locale-base-debuginfo-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-profile-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-utils-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-utils-debuginfo-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-utils-src-debugsource-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nscd-2.26-13.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nscd-debuginfo-2.26-13.19.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
