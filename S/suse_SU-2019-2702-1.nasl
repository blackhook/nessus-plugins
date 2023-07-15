#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2702-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(130002);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-14250", "CVE-2019-15847");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : gcc7 (SUSE-SU-2019:2702-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for gcc7 to r275405 fixes the following issues :

Security issues fixed :

CVE-2019-14250: Fixed an integer overflow in binutils (bsc#1142649).

CVE-2019-15847: Fixed an optimization in the POWER9 backend of gcc
that could reduce the entropy of the random number generator
(bsc#1149145).

Non-security issue fixed: Move Live Patching technology stack from
kGraft to upstream klp (bsc#1071995, fate#323487).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1071995"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1148517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1149145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-14250/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-15847/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192702-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98ddf222"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-2702=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-2702=1

SUSE Linux Enterprise Module for Development Tools 15-SP1:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-SP1-2019-2702=1

SUSE Linux Enterprise Module for Development Tools 15:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-2019-2702=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-2702=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-2702=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cpp7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cpp7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-aarch64-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-aarch64-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-aarch64-gcc7-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-aarch64-gcc7-icecream-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-arm-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-arm-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-arm-gcc7-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-arm-none-gcc7-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-arm-none-gcc7-bootstrap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-arm-none-gcc7-bootstrap-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-avr-gcc7-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-avr-gcc7-bootstrap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-avr-gcc7-bootstrap-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-epiphany-gcc7-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-epiphany-gcc7-bootstrap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-epiphany-gcc7-bootstrap-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-hppa-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-hppa-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-hppa-gcc7-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-hppa-gcc7-icecream-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-i386-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-i386-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-i386-gcc7-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-i386-gcc7-icecream-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-m68k-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-m68k-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-m68k-gcc7-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-m68k-gcc7-icecream-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-mips-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-mips-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-mips-gcc7-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-mips-gcc7-icecream-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-nvptx-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-nvptx-newlib7-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-ppc64-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-ppc64-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-ppc64-gcc7-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-ppc64-gcc7-icecream-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-ppc64le-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-ppc64le-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-ppc64le-gcc7-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-ppc64le-gcc7-icecream-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-rx-gcc7-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-rx-gcc7-bootstrap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-rx-gcc7-bootstrap-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-s390x-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-s390x-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-s390x-gcc7-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-s390x-gcc7-icecream-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-sparc-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-sparc-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-sparc-gcc7-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-sparc64-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-sparc64-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-sparc64-gcc7-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-sparc64-gcc7-icecream-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-sparcv9-gcc7-icecream-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-x86_64-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-x86_64-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-x86_64-gcc7-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-x86_64-gcc7-icecream-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-ada");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-ada-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-c++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-fortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-fortran-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-go-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-obj-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-obj-c++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-objc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc7-testresults");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libada7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libada7-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libada7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libatomic1-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libatomic1-gcc7-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libatomic1-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcilkrts5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcilkrts5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcilkrts5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcc_s1-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcc_s1-gcc7-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcc_s1-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgfortran4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgfortran4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgfortran4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgo11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgo11-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgo11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgomp1-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgomp1-gcc7-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgomp1-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libitm1-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libitm1-gcc7-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libitm1-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liblsan0-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liblsan0-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmpx2-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmpx2-gcc7-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmpx2-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmpxwrappers2-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmpxwrappers2-gcc7-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmpxwrappers2-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libobjc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libobjc4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libobjc4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libquadmath0-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libquadmath0-gcc7-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libquadmath0-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-devel-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-gcc7-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-gcc7-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtsan0-gcc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtsan0-gcc7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libubsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libubsan0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libubsan0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/17");
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
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"cross-nvptx-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"cross-nvptx-newlib7-devel-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"cross-s390x-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"cross-s390x-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"cross-s390x-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"cross-s390x-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"gcc7-c++-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"gcc7-fortran-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libasan4-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libasan4-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libcilkrts5-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libcilkrts5-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libcilkrts5-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libcilkrts5-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgfortran4-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgfortran4-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"liblsan0-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"liblsan0-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libmpx2-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libmpx2-gcc7-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libmpx2-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libmpx2-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libmpxwrappers2-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libmpxwrappers2-gcc7-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libmpxwrappers2-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libmpxwrappers2-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libquadmath0-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libquadmath0-gcc7-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libquadmath0-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libquadmath0-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libstdc++6-devel-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libtsan0-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libtsan0-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libubsan0-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libubsan0-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"cross-x86_64-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"cross-x86_64-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"cross-x86_64-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"cross-x86_64-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"gcc7-c++-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"gcc7-fortran-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"libasan4-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"libasan4-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"libgfortran4-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"libgfortran4-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"libstdc++6-devel-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"libubsan0-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"libubsan0-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cpp7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cpp7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-aarch64-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-aarch64-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-aarch64-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-aarch64-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-arm-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-arm-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-arm-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-arm-none-gcc7-bootstrap-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-arm-none-gcc7-bootstrap-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-arm-none-gcc7-bootstrap-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-avr-gcc7-bootstrap-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-avr-gcc7-bootstrap-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-avr-gcc7-bootstrap-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-epiphany-gcc7-bootstrap-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-epiphany-gcc7-bootstrap-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-epiphany-gcc7-bootstrap-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-hppa-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-hppa-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-hppa-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-hppa-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-i386-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-i386-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-i386-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-i386-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-m68k-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-m68k-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-m68k-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-m68k-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-mips-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-mips-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-mips-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-mips-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-ppc64-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-ppc64-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-ppc64-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-ppc64-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-ppc64le-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-ppc64le-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-ppc64le-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-ppc64le-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-rx-gcc7-bootstrap-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-rx-gcc7-bootstrap-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-rx-gcc7-bootstrap-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-sparc-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-sparc-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-sparc-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-sparc64-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-sparc64-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-sparc64-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-sparc64-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-sparcv9-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-ada-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-ada-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-ada-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-c++-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-c++-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-fortran-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-fortran-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-go-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-go-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-go-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-locale-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-obj-c++-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-obj-c++-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-obj-c++-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-objc-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-objc-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-objc-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc7-testresults-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libada7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libada7-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libada7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libada7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libasan4-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libasan4-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libatomic1-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libatomic1-gcc7-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libatomic1-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libatomic1-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgcc_s1-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgcc_s1-gcc7-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgcc_s1-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgcc_s1-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgfortran4-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgfortran4-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgo11-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgo11-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgo11-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgo11-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgomp1-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgomp1-gcc7-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgomp1-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgomp1-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libitm1-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libitm1-gcc7-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libitm1-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libitm1-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libobjc4-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libobjc4-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libobjc4-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libobjc4-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-devel-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-gcc7-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-gcc7-locale-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libubsan0-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libubsan0-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"cross-nvptx-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"cross-nvptx-newlib7-devel-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"gcc7-c++-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"gcc7-fortran-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libasan4-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libasan4-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libcilkrts5-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libcilkrts5-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libcilkrts5-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libcilkrts5-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libgfortran4-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libgfortran4-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libstdc++6-devel-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libubsan0-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libubsan0-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc7-c++-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc7-fortran-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libasan4-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgfortran4-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libstdc++6-devel-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libubsan0-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cpp7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cpp7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-arm-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-arm-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-arm-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-arm-none-gcc7-bootstrap-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-arm-none-gcc7-bootstrap-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-arm-none-gcc7-bootstrap-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-avr-gcc7-bootstrap-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-avr-gcc7-bootstrap-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-avr-gcc7-bootstrap-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-epiphany-gcc7-bootstrap-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-epiphany-gcc7-bootstrap-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-epiphany-gcc7-bootstrap-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-hppa-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-hppa-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-hppa-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-hppa-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-i386-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-i386-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-i386-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-i386-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-m68k-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-m68k-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-m68k-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-m68k-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-mips-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-mips-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-mips-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-mips-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-ppc64-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-ppc64-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-ppc64-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-ppc64-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-rx-gcc7-bootstrap-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-rx-gcc7-bootstrap-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-rx-gcc7-bootstrap-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-sparc-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-sparc-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-sparc-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-sparc64-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-sparc64-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-sparc64-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-sparc64-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cross-sparcv9-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc7-ada-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc7-ada-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc7-ada-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc7-c++-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc7-c++-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc7-fortran-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc7-fortran-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc7-go-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc7-go-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc7-go-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc7-locale-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc7-obj-c++-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc7-obj-c++-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc7-obj-c++-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc7-objc-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc7-objc-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc7-objc-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gcc7-testresults-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libada7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libada7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libada7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libasan4-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libasan4-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgfortran4-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgfortran4-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgo11-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgo11-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgo11-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libobjc4-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libobjc4-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libobjc4-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libstdc++6-devel-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libubsan0-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libubsan0-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"cross-nvptx-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"cross-nvptx-newlib7-devel-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"cross-s390x-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"cross-s390x-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"cross-s390x-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"cross-s390x-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"gcc7-c++-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"gcc7-fortran-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libasan4-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libasan4-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libcilkrts5-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libcilkrts5-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libcilkrts5-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libcilkrts5-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgfortran4-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgfortran4-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"liblsan0-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"liblsan0-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libmpx2-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libmpx2-gcc7-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libmpx2-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libmpx2-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libmpxwrappers2-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libmpxwrappers2-gcc7-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libmpxwrappers2-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libmpxwrappers2-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libquadmath0-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libquadmath0-gcc7-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libquadmath0-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libquadmath0-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libstdc++6-devel-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libtsan0-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libtsan0-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libubsan0-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libubsan0-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"cross-x86_64-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"cross-x86_64-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"cross-x86_64-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"cross-x86_64-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"gcc7-c++-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"gcc7-fortran-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"libasan4-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"libasan4-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"libgfortran4-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"libgfortran4-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"libstdc++6-devel-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"libubsan0-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"libubsan0-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cpp7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cpp7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-aarch64-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-aarch64-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-aarch64-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-aarch64-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-arm-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-arm-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-arm-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-arm-none-gcc7-bootstrap-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-arm-none-gcc7-bootstrap-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-arm-none-gcc7-bootstrap-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-avr-gcc7-bootstrap-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-avr-gcc7-bootstrap-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-avr-gcc7-bootstrap-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-epiphany-gcc7-bootstrap-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-epiphany-gcc7-bootstrap-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-epiphany-gcc7-bootstrap-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-hppa-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-hppa-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-hppa-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-hppa-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-i386-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-i386-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-i386-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-i386-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-m68k-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-m68k-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-m68k-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-m68k-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-mips-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-mips-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-mips-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-mips-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-ppc64-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-ppc64-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-ppc64-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-ppc64-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-ppc64le-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-ppc64le-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-ppc64le-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-ppc64le-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-rx-gcc7-bootstrap-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-rx-gcc7-bootstrap-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-rx-gcc7-bootstrap-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-sparc-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-sparc-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-sparc-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-sparc64-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-sparc64-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-sparc64-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-sparc64-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-sparcv9-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-ada-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-ada-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-ada-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-c++-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-c++-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-fortran-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-fortran-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-go-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-go-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-go-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-locale-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-obj-c++-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-obj-c++-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-obj-c++-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-objc-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-objc-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-objc-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc7-testresults-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libada7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libada7-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libada7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libada7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libasan4-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libasan4-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libatomic1-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libatomic1-gcc7-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libatomic1-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libatomic1-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgcc_s1-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgcc_s1-gcc7-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgcc_s1-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgcc_s1-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgfortran4-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgfortran4-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgo11-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgo11-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgo11-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgo11-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgomp1-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgomp1-gcc7-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgomp1-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgomp1-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libitm1-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libitm1-gcc7-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libitm1-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libitm1-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libobjc4-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libobjc4-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libobjc4-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libobjc4-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-devel-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-gcc7-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-gcc7-locale-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libubsan0-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libubsan0-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"cross-nvptx-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"cross-nvptx-newlib7-devel-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"gcc7-c++-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"gcc7-fortran-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libasan4-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libasan4-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libcilkrts5-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libcilkrts5-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libcilkrts5-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libcilkrts5-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libgfortran4-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libgfortran4-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libstdc++6-devel-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libubsan0-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libubsan0-32bit-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"s390x", reference:"gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"s390x", reference:"gcc7-c++-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"s390x", reference:"gcc7-fortran-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"s390x", reference:"libasan4-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"s390x", reference:"libgfortran4-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"s390x", reference:"libstdc++6-devel-gcc7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"s390x", reference:"libubsan0-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cpp7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cpp7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-arm-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-arm-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-arm-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-arm-none-gcc7-bootstrap-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-arm-none-gcc7-bootstrap-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-arm-none-gcc7-bootstrap-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-avr-gcc7-bootstrap-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-avr-gcc7-bootstrap-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-avr-gcc7-bootstrap-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-epiphany-gcc7-bootstrap-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-epiphany-gcc7-bootstrap-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-epiphany-gcc7-bootstrap-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-hppa-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-hppa-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-hppa-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-hppa-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-i386-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-i386-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-i386-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-i386-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-m68k-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-m68k-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-m68k-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-m68k-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-mips-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-mips-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-mips-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-mips-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-ppc64-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-ppc64-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-ppc64-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-ppc64-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-rx-gcc7-bootstrap-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-rx-gcc7-bootstrap-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-rx-gcc7-bootstrap-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-sparc-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-sparc-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-sparc-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-sparc64-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-sparc64-gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-sparc64-gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-sparc64-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cross-sparcv9-gcc7-icecream-backend-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc7-ada-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc7-ada-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc7-ada-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc7-c++-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc7-c++-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc7-debugsource-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc7-fortran-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc7-fortran-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc7-go-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc7-go-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc7-go-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc7-locale-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc7-obj-c++-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc7-obj-c++-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc7-obj-c++-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc7-objc-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc7-objc-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc7-objc-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gcc7-testresults-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libada7-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libada7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libada7-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libasan4-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libasan4-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgfortran4-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgfortran4-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgo11-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgo11-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgo11-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libobjc4-32bit-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libobjc4-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libobjc4-debuginfo-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libstdc++6-devel-gcc7-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libubsan0-7.4.1+r275405-4.9.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libubsan0-debuginfo-7.4.1+r275405-4.9.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gcc7");
}
