#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0300-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106530);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000376");

  script_name(english:"SUSE SLES11 Security Update : gcc43 (SUSE-SU-2018:0300-1) (Stack Clash)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gcc43 fixes the following issues: Security issue 
fixed :

  - CVE-2017-1000376: Don't request excutable stack from
    libffi. [bnc#1045091] New features :

  - Add support for retpolines to mitigate the Spectre
    Variant 2 attack. [bnc#1074621]

  - Add support for zero-sized VLAs and allocas with

    -fstack-clash-protection. [bnc#1059075]

  - Add support for -fstack-clash-protection to mitigate the
    Stack Clash attack. [bnc#1039513] Non security bugs
    fixed :

  - Fixed build of 32bit libgcov.a with LFS support.
    [bsc#1044016]

  - Fixed issue with libstdc++ functional when an exception
    is thrown during construction. [bsc#999596]

  - Fixed issue with using gcov and #pragma pack.
    [bsc#977654]

  - Fixed ICE compiling AFS modules for the s390x kernel.
    [bsc#938159]

  - Backport large file support from GCC 4.6.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1044016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1059075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=938159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=977654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=999596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-1000376/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180300-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb0aec83"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-gcc43-13448=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-gcc43-13448=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-gcc43-13448=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-gcc43-13448=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-gcc43-13448=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-gcc43-13448=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cpp43");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc43");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc43-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc43-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc43-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++43-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/31");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"gcc43-32bit-4.3.4_20091019-37.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libstdc++43-devel-32bit-4.3.4_20091019-37.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"gcc43-32bit-4.3.4_20091019-37.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libstdc++43-devel-32bit-4.3.4_20091019-37.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"cpp43-4.3.4_20091019-37.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"gcc43-4.3.4_20091019-37.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"gcc43-c++-4.3.4_20091019-37.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"gcc43-info-4.3.4_20091019-37.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"gcc43-locale-4.3.4_20091019-37.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libstdc++43-devel-4.3.4_20091019-37.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"gcc43-32bit-4.3.4_20091019-37.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libstdc++43-devel-32bit-4.3.4_20091019-37.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"gcc43-32bit-4.3.4_20091019-37.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libstdc++43-devel-32bit-4.3.4_20091019-37.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"cpp43-4.3.4_20091019-37.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"gcc43-4.3.4_20091019-37.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"gcc43-c++-4.3.4_20091019-37.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"gcc43-info-4.3.4_20091019-37.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"gcc43-locale-4.3.4_20091019-37.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libstdc++43-devel-4.3.4_20091019-37.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gcc43");
}
