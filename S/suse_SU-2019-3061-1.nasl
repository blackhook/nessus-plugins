#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:3061-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(131311);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-14250", "CVE-2019-15847");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : gcc9 (SUSE-SU-2019:3061-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update includes the GNU Compiler Collection 9.

A full changelog is provided by the GCC team on :

https://www.gnu.org/software/gcc/gcc-9/changes.html

The base system compiler libraries libgcc_s1, libstdc++6 and others
are now built by the gcc 9 packages.

To use it, install 'gcc9' or 'gcc9-c++' or other compiler brands and
use CC=gcc-9 / CXX=g++-9 during configuration for using it.

Security issues fixed :

CVE-2019-15847: Fixed a miscompilation in the POWER9 back end, that
optimized multiple calls of the __builtin_darn intrinsic into a single
call. (bsc#1149145)

CVE-2019-14250: Fixed a heap overflow in the LTO linker. (bsc#1142649)

Non-security issues fixed: Split out libstdc++ pretty-printers into a
separate package supplementing gdb and the installed runtime.
(bsc#1135254)

Fixed miscompilation for vector shift on s390. (bsc#1141897)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1114592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1135254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1141897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1142649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1142654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1148517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1149145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.gnu.org/software/gcc/gcc-9/changes.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-14250/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-15847/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20193061-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5aad195f"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-3061=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-3061=1

SUSE Linux Enterprise Module for Development Tools 15-SP1:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-SP1-2019-3061=1

SUSE Linux Enterprise Module for Development Tools 15:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-2019-3061=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-3061=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-3061=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cpp9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cpp9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc9-ada");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc9-ada-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc9-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc9-c++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc9-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc9-fortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc9-fortran-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc9-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc9-go-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc9-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libada9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libada9-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libada9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libatomic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libatomic1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libatomic1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcc_s1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcc_s1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcc_s1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgfortran5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgfortran5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgfortran5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgo14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgo14-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgo14-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgomp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgomp1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgomp1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libitm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libitm1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libitm1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liblsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liblsan0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libquadmath0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libquadmath0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libquadmath0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-devel-gcc9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-pp-gcc9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtsan0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libubsan1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libubsan1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libubsan1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/26");
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
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"liblsan0-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"liblsan0-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libquadmath0-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libquadmath0-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libquadmath0-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libquadmath0-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libtsan0-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libtsan0-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cpp9-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cpp9-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc9-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc9-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc9-ada-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc9-ada-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc9-ada-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc9-c++-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc9-c++-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc9-c++-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc9-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc9-debugsource-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc9-fortran-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc9-fortran-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc9-fortran-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc9-go-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc9-go-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc9-go-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc9-locale-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libada9-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libada9-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libada9-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libada9-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libasan5-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libasan5-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libasan5-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libasan5-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libatomic1-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libatomic1-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libatomic1-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libatomic1-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgcc_s1-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgcc_s1-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgcc_s1-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgcc_s1-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgfortran5-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgfortran5-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgfortran5-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgfortran5-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgo14-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgo14-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgo14-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgo14-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgomp1-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgomp1-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgomp1-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgomp1-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libitm1-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libitm1-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libitm1-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libitm1-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-devel-gcc9-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-devel-gcc9-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-locale-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-pp-gcc9-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-pp-gcc9-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libubsan1-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libubsan1-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libubsan1-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libubsan1-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"liblsan0-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"liblsan0-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libquadmath0-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libquadmath0-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libquadmath0-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libquadmath0-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libtsan0-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libtsan0-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cpp9-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cpp9-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc9-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc9-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc9-ada-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc9-ada-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc9-ada-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc9-c++-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc9-c++-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc9-c++-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc9-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc9-debugsource-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc9-fortran-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc9-fortran-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc9-fortran-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc9-go-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc9-go-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc9-go-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc9-locale-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libada9-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libada9-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libada9-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libada9-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libasan5-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libasan5-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libasan5-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libasan5-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libatomic1-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libatomic1-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libatomic1-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libatomic1-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgcc_s1-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgcc_s1-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgcc_s1-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgcc_s1-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgfortran5-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgfortran5-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgfortran5-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgfortran5-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgo14-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgo14-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgo14-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgo14-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgomp1-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgomp1-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgomp1-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgomp1-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libitm1-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libitm1-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libitm1-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libitm1-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libstdc++6-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libstdc++6-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libstdc++6-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libstdc++6-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libstdc++6-devel-gcc9-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libstdc++6-devel-gcc9-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libstdc++6-locale-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libstdc++6-pp-gcc9-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libstdc++6-pp-gcc9-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libubsan1-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libubsan1-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libubsan1-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libubsan1-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"liblsan0-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"liblsan0-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libquadmath0-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libquadmath0-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libquadmath0-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libquadmath0-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libtsan0-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libtsan0-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cpp9-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cpp9-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc9-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc9-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc9-ada-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc9-ada-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc9-ada-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc9-c++-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc9-c++-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc9-c++-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc9-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc9-debugsource-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc9-fortran-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc9-fortran-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc9-fortran-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc9-go-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc9-go-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc9-go-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc9-locale-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libada9-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libada9-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libada9-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libada9-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libasan5-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libasan5-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libasan5-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libasan5-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libatomic1-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libatomic1-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libatomic1-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libatomic1-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgcc_s1-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgcc_s1-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgcc_s1-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgcc_s1-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgfortran5-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgfortran5-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgfortran5-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgfortran5-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgo14-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgo14-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgo14-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgo14-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgomp1-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgomp1-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgomp1-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgomp1-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libitm1-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libitm1-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libitm1-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libitm1-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-devel-gcc9-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-devel-gcc9-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-locale-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-pp-gcc9-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-pp-gcc9-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libubsan1-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libubsan1-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libubsan1-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libubsan1-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"liblsan0-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"liblsan0-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libquadmath0-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libquadmath0-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libquadmath0-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libquadmath0-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libtsan0-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libtsan0-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cpp9-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cpp9-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc9-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc9-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc9-ada-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc9-ada-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc9-ada-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc9-c++-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc9-c++-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc9-c++-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc9-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc9-debugsource-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc9-fortran-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc9-fortran-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc9-fortran-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc9-go-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc9-go-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc9-go-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc9-locale-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libada9-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libada9-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libada9-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libada9-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libasan5-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libasan5-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libasan5-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libasan5-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libatomic1-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libatomic1-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libatomic1-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libatomic1-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgcc_s1-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgcc_s1-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgcc_s1-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgcc_s1-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgfortran5-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgfortran5-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgfortran5-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgfortran5-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgo14-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgo14-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgo14-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgo14-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgomp1-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgomp1-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgomp1-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgomp1-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libitm1-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libitm1-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libitm1-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libitm1-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libstdc++6-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libstdc++6-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libstdc++6-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libstdc++6-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libstdc++6-devel-gcc9-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libstdc++6-devel-gcc9-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libstdc++6-locale-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libstdc++6-pp-gcc9-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libstdc++6-pp-gcc9-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libubsan1-32bit-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libubsan1-32bit-debuginfo-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libubsan1-9.2.1+r275327-1.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libubsan1-debuginfo-9.2.1+r275327-1.3.7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gcc9");
}
