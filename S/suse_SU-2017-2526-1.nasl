#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2526-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103355);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-11671");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : gcc48 (SUSE-SU-2017:2526-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gcc48 fixes the following issues: Security issues
fixed :

  - A new option -fstack-clash-protection is now offered,
    which mitigates the stack clash type of attacks.
    [bnc#1039513] Future maintenance releases of packages
    will be built with this option.

  - CVE-2017-11671: Fixed rdrand/rdseed code generation
    issue [bsc#1050947] Bugs fixed :

  - Enable LFS support in 32bit libgcov.a. [bsc#1044016]

  - Bump libffi version in libffi.pc to 3.0.11.

  - Fix libffi issue for armv7l. [bsc#988274]

  - Properly diagnose missing -fsanitize=address support on
    ppc64le. [bnc#1028744]

  - Backport patch for PR65612. [bnc#1022062]

  - Fixed DR#1288. [bnc#1011348]

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1011348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1022062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1028744"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=988274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11671/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172526-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a66d5ada"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 6:zypper in -t patch
SUSE-OpenStack-Cloud-6-2017-1564=1

SUSE Linux Enterprise Workstation Extension 12-SP3:zypper in -t patch
SUSE-SLE-WE-12-SP3-2017-1564=1

SUSE Linux Enterprise Workstation Extension 12-SP2:zypper in -t patch
SUSE-SLE-WE-12-SP2-2017-1564=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2017-1564=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-1564=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2017-1564=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-1564=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2017-1564=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-1564=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2017-1564=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2017-1564=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2017-1564=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-1564=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cpp48");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cpp48-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc48");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc48-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc48-c++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc48-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc48-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc48-gij");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc48-gij-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc48-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcj48");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcj48-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcj48-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcj48-jar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcj_bc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++48-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0|1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1/2/3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libasan0-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libasan0-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libasan0-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"cpp48-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"cpp48-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"gcc48-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"gcc48-c++-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"gcc48-c++-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"gcc48-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"gcc48-debugsource-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"gcc48-locale-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libstdc++48-devel-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"gcc48-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libstdc++48-devel-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libasan0-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libasan0-32bit-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libasan0-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libasan0-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cpp48-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cpp48-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"gcc48-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"gcc48-c++-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"gcc48-c++-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"gcc48-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"gcc48-debugsource-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"gcc48-locale-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libstdc++48-devel-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"gcc48-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libstdc++48-devel-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"libasan0-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"libasan0-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"libasan0-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"cpp48-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"cpp48-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"gcc48-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"gcc48-debugsource-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"gcc48-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"gcc48-c++-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"gcc48-c++-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"gcc48-locale-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libstdc++48-devel-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"gcc48-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libstdc++48-devel-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libasan0-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libasan0-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libasan0-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"cpp48-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"cpp48-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"gcc48-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"gcc48-debugsource-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"gcc48-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"gcc48-c++-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"gcc48-c++-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"gcc48-locale-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libstdc++48-devel-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"gcc48-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libstdc++48-devel-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"cpp48-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"cpp48-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gcc48-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gcc48-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gcc48-c++-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gcc48-c++-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gcc48-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gcc48-debugsource-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gcc48-gij-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gcc48-gij-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gcc48-gij-debuginfo-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gcc48-gij-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libasan0-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libasan0-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libasan0-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgcj48-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgcj48-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgcj48-debuginfo-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgcj48-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgcj48-debugsource-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgcj48-jar-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgcj_bc1-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libstdc++48-devel-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libstdc++48-devel-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"cpp48-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"cpp48-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"gcc48-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"gcc48-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"gcc48-c++-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"gcc48-c++-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"gcc48-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"gcc48-debugsource-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"gcc48-gij-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"gcc48-gij-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"gcc48-gij-debuginfo-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"gcc48-gij-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libasan0-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libasan0-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libasan0-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libgcj48-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libgcj48-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libgcj48-debuginfo-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libgcj48-debuginfo-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libgcj48-debugsource-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libgcj48-jar-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libgcj_bc1-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libstdc++48-devel-32bit-4.8.5-31.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libstdc++48-devel-4.8.5-31.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gcc48");
}
