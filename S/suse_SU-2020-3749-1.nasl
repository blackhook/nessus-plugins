#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3749-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(144100);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2020-13844");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : gcc7 (SUSE-SU-2020:3749-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for gcc7 fixes the following issues :

CVE-2020-13844: Added mitigation for aarch64 Straight Line Speculation
issue (bsc#1172798)

Enable fortran for the nvptx offload compiler.

Update README.First-for.SuSE.packagers

avoid assembler errors with AVX512 gather and scatter instructions
when using -masm=intel.

Backport the aarch64 -moutline-atomics feature and accumulated fixes
but not its default enabling. [jsc#SLE-12209, bsc#1167939]

Fixed 32bit libgnat.so link. [bsc#1178675]

Fixed memcpy miscompilation on aarch64. [bsc#1178624, bsc#1178577]

Fixed debug line info for try/catch. [bsc#1178614]

Remove -mbranch-protection=standard (aarch64 flag) when gcc7 is used
to build gcc7 (ie when ada is enabled)

Fixed corruption of pass private ->aux via DF. [gcc#94148]

Fixed debug information issue with inlined functions and passed by
reference arguments. [gcc#93888]

Fixed binutils release date detection issue.

Fixed register allocation issue with exception handling code on s390x.
[bsc#1161913]

Fixed miscompilation of some atomic code on aarch64. [bsc#1150164]

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1150164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1161913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1167939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-13844/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203749-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02df1406"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2020-3749=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2020-3749=1

SUSE Linux Enterprise Module for Development Tools 15-SP3 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-15-SP3-2020-3749=1

SUSE Linux Enterprise Module for Development Tools 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-15-SP2-2020-3749=1

SUSE Linux Enterprise Module for Development Tools 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-15-SP1-2020-3749=1

SUSE Linux Enterprise Module for Basesystem 15-SP3 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP3-2020-3749=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2020-3749=1

SUSE Linux Enterprise Module for Basesystem 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP1-2020-3749=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-3749=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-3749=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cpp7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cpp7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-nvptx-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-nvptx-newlib7-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-ada");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-ada-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-c++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-fortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-fortran-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-objc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libada7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libada7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcilkrts5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcilkrts5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcilkrts5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgfortran4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgfortran4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgfortran4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-devel-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libubsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libubsan0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libubsan0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/11");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1/2/3", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1/2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"cross-nvptx-gcc7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"cross-nvptx-newlib7-devel-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"gcc7-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"gcc7-c++-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"gcc7-fortran-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libasan4-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libasan4-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libcilkrts5-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libcilkrts5-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libcilkrts5-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libcilkrts5-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgfortran4-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgfortran4-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libstdc++6-devel-gcc7-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libubsan0-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libubsan0-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cpp7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cpp7-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-ada-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-ada-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-c++-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-c++-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-debugsource-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-fortran-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-fortran-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-locale-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-objc-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-objc-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libada7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libada7-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libasan4-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libasan4-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgfortran4-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgfortran4-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-devel-gcc7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libubsan0-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libubsan0-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"cross-nvptx-gcc7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"cross-nvptx-newlib7-devel-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"gcc7-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"gcc7-c++-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"gcc7-fortran-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"libasan4-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"libasan4-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"libcilkrts5-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"libcilkrts5-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"libcilkrts5-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"libcilkrts5-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"libgfortran4-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"libgfortran4-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"libstdc++6-devel-gcc7-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"libubsan0-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"libubsan0-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"cpp7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"cpp7-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"gcc7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"gcc7-ada-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"gcc7-ada-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"gcc7-c++-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"gcc7-c++-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"gcc7-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"gcc7-debugsource-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"gcc7-fortran-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"gcc7-fortran-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"gcc7-locale-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"gcc7-objc-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"gcc7-objc-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libada7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libada7-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libasan4-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libasan4-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libgfortran4-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libgfortran4-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libstdc++6-devel-gcc7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libubsan0-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libubsan0-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"cpp7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"cpp7-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc7-ada-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc7-ada-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc7-c++-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc7-c++-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc7-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc7-debugsource-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc7-fortran-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc7-fortran-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc7-locale-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc7-objc-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc7-objc-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libada7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libada7-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libasan4-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libasan4-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgfortran4-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgfortran4-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libstdc++6-devel-gcc7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libubsan0-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libubsan0-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"cross-nvptx-gcc7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"cross-nvptx-newlib7-devel-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"gcc7-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"gcc7-c++-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"gcc7-fortran-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libasan4-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libasan4-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libcilkrts5-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libcilkrts5-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libcilkrts5-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libcilkrts5-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libgfortran4-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libgfortran4-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libstdc++6-devel-gcc7-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libubsan0-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libubsan0-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"cpp7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"cpp7-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc7-ada-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc7-ada-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc7-c++-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc7-c++-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc7-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc7-debugsource-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc7-fortran-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc7-fortran-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc7-locale-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc7-objc-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc7-objc-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libada7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libada7-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libasan4-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libasan4-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgfortran4-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgfortran4-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libstdc++6-devel-gcc7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libubsan0-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libubsan0-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"cross-nvptx-gcc7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"cross-nvptx-newlib7-devel-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"gcc7-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"gcc7-c++-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"gcc7-fortran-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libasan4-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libasan4-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libcilkrts5-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libcilkrts5-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libcilkrts5-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libcilkrts5-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgfortran4-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgfortran4-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libstdc++6-devel-gcc7-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libubsan0-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libubsan0-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cpp7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cpp7-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-ada-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-ada-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-c++-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-c++-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-debugsource-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-fortran-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-fortran-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-locale-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-objc-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-objc-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libada7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libada7-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libasan4-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libasan4-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgfortran4-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgfortran4-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-devel-gcc7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libubsan0-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libubsan0-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", cpu:"x86_64", reference:"cross-nvptx-gcc7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", cpu:"x86_64", reference:"cross-nvptx-newlib7-devel-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", cpu:"x86_64", reference:"gcc7-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", cpu:"x86_64", reference:"gcc7-c++-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", cpu:"x86_64", reference:"gcc7-fortran-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", cpu:"x86_64", reference:"libasan4-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", cpu:"x86_64", reference:"libasan4-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", cpu:"x86_64", reference:"libcilkrts5-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", cpu:"x86_64", reference:"libcilkrts5-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", cpu:"x86_64", reference:"libcilkrts5-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", cpu:"x86_64", reference:"libcilkrts5-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", cpu:"x86_64", reference:"libgfortran4-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", cpu:"x86_64", reference:"libgfortran4-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", cpu:"x86_64", reference:"libstdc++6-devel-gcc7-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", cpu:"x86_64", reference:"libubsan0-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", cpu:"x86_64", reference:"libubsan0-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"cpp7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"cpp7-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"gcc7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"gcc7-ada-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"gcc7-ada-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"gcc7-c++-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"gcc7-c++-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"gcc7-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"gcc7-debugsource-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"gcc7-fortran-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"gcc7-fortran-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"gcc7-locale-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"gcc7-objc-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"gcc7-objc-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libada7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libada7-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libasan4-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libasan4-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libgfortran4-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libgfortran4-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libstdc++6-devel-gcc7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libubsan0-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libubsan0-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"cross-nvptx-gcc7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"cross-nvptx-newlib7-devel-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"gcc7-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"gcc7-c++-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"gcc7-fortran-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libasan4-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libasan4-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libcilkrts5-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libcilkrts5-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libcilkrts5-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libcilkrts5-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libgfortran4-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libgfortran4-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libstdc++6-devel-gcc7-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libubsan0-32bit-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libubsan0-32bit-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"cpp7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"cpp7-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc7-ada-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc7-ada-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc7-c++-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc7-c++-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc7-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc7-debugsource-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc7-fortran-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc7-fortran-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc7-locale-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc7-objc-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc7-objc-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libada7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libada7-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libasan4-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libasan4-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgfortran4-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgfortran4-debuginfo-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libstdc++6-devel-gcc7-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libubsan0-7.5.0+r278197-4.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libubsan0-debuginfo-7.5.0+r278197-4.19.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gcc7");
}
