#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:2947-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(143609);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2020-13844");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : gcc10, nvptx-tools (SUSE-SU-2020:2947-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for gcc10, nvptx-tools fixes the following issues :

This update provides the GCC10 compiler suite and runtime libraries.

The base SUSE Linux Enterprise libraries libgcc_s1, libstdc++6 are
replaced by the gcc10 variants.

The new compiler variants are available with '-10' suffix, you can
specify them via :

&#9;CC=gcc-10 CXX=g++-10

or similar commands.

For a detailed changelog check out
https://gcc.gnu.org/gcc-10/changes.html

Changes in nvptx-tools :

Enable build on aarch64

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1173972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1174753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1174817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1175168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://gcc.gnu.org/gcc-10/changes.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-13844/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20202947-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2491f88"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2020-2947=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2020-2947=1

SUSE Linux Enterprise Module for Development Tools 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-15-SP2-2020-2947=1

SUSE Linux Enterprise Module for Development Tools 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-15-SP1-2020-2947=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2020-2947=1

SUSE Linux Enterprise Module for Basesystem 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP1-2020-2947=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-2947=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-2947=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cpp10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cpp10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-nvptx-gcc10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-nvptx-newlib10-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc10-ada");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc10-ada-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc10-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc10-c++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc10-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc10-fortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc10-fortran-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc10-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc10-go-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc10-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libada10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libada10-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libada10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libatomic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libatomic1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libatomic1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcc_s1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcc_s1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcc_s1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgfortran5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgfortran5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgfortran5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgo16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgo16-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgo16-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-devel-gcc10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-pp-gcc10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtsan0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libubsan1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libubsan1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libubsan1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nvptx-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nvptx-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nvptx-tools-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1/2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"cross-nvptx-gcc10-10.2.1+git583-1.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"cross-nvptx-newlib10-devel-10.2.1+git583-1.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"liblsan0-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"liblsan0-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libquadmath0-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libquadmath0-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libquadmath0-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libquadmath0-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libtsan0-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libtsan0-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"nvptx-tools-1.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"nvptx-tools-debuginfo-1.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"nvptx-tools-debugsource-1.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cpp10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cpp10-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc10-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc10-ada-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc10-ada-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc10-ada-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc10-c++-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc10-c++-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc10-c++-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc10-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc10-debugsource-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc10-fortran-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc10-fortran-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc10-fortran-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc10-go-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc10-go-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc10-go-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gcc10-locale-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libada10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libada10-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libada10-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libada10-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libasan6-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libasan6-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libasan6-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libasan6-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libatomic1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libatomic1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libatomic1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libatomic1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgcc_s1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgcc_s1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgcc_s1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgcc_s1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgfortran5-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgfortran5-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgfortran5-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgfortran5-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgo16-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgo16-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgo16-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgo16-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgomp1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgomp1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgomp1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgomp1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libitm1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libitm1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libitm1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libitm1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-devel-gcc10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-devel-gcc10-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-locale-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-pp-gcc10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libstdc++6-pp-gcc10-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libubsan1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libubsan1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libubsan1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libubsan1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"cpp10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"cpp10-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc10-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc10-ada-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc10-ada-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc10-ada-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc10-c++-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc10-c++-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc10-c++-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc10-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc10-debugsource-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc10-fortran-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc10-fortran-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc10-fortran-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc10-go-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc10-go-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc10-go-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gcc10-locale-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libada10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libada10-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libada10-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libada10-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libasan6-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libasan6-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libasan6-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libasan6-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libatomic1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libatomic1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libatomic1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libatomic1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgcc_s1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgcc_s1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgcc_s1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgcc_s1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgfortran5-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgfortran5-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgfortran5-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgfortran5-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgo16-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgo16-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgo16-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgo16-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgomp1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgomp1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgomp1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgomp1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libitm1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libitm1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libitm1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libitm1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libstdc++6-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libstdc++6-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libstdc++6-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libstdc++6-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libstdc++6-devel-gcc10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libstdc++6-devel-gcc10-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libstdc++6-locale-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libstdc++6-pp-gcc10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libstdc++6-pp-gcc10-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libubsan1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libubsan1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libubsan1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libubsan1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"gcc10-ada-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libada10-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libada10-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"liblsan0-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"liblsan0-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libquadmath0-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libquadmath0-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libquadmath0-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libquadmath0-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libstdc++6-pp-gcc10-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libtsan0-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libtsan0-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"nvptx-tools-1.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"nvptx-tools-debuginfo-1.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"nvptx-tools-debugsource-1.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"cpp10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"cpp10-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc10-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc10-ada-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc10-ada-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc10-c++-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc10-c++-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc10-c++-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc10-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc10-debugsource-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc10-fortran-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc10-fortran-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc10-fortran-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc10-go-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc10-go-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc10-go-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gcc10-locale-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libada10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libada10-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libasan6-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libasan6-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libasan6-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libasan6-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libatomic1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libatomic1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libatomic1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libatomic1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgcc_s1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgcc_s1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgcc_s1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgcc_s1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgfortran5-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgfortran5-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgfortran5-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgfortran5-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgo16-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgo16-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgo16-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgo16-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgomp1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgomp1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgomp1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgomp1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libitm1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libitm1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libitm1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libitm1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libstdc++6-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libstdc++6-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libstdc++6-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libstdc++6-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libstdc++6-devel-gcc10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libstdc++6-devel-gcc10-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libstdc++6-locale-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libstdc++6-pp-gcc10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libubsan1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libubsan1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libubsan1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libubsan1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"cross-nvptx-gcc10-10.2.1+git583-1.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"cross-nvptx-newlib10-devel-10.2.1+git583-1.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"liblsan0-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"liblsan0-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libquadmath0-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libquadmath0-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libquadmath0-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libquadmath0-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libtsan0-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libtsan0-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"nvptx-tools-1.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"nvptx-tools-debuginfo-1.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"nvptx-tools-debugsource-1.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cpp10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cpp10-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc10-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc10-ada-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc10-ada-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc10-ada-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc10-c++-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc10-c++-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc10-c++-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc10-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc10-debugsource-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc10-fortran-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc10-fortran-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc10-fortran-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc10-go-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc10-go-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc10-go-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gcc10-locale-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libada10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libada10-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libada10-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libada10-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libasan6-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libasan6-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libasan6-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libasan6-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libatomic1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libatomic1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libatomic1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libatomic1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgcc_s1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgcc_s1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgcc_s1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgcc_s1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgfortran5-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgfortran5-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgfortran5-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgfortran5-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgo16-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgo16-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgo16-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgo16-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgomp1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgomp1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgomp1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgomp1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libitm1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libitm1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libitm1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libitm1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-devel-gcc10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-devel-gcc10-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-locale-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-pp-gcc10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libstdc++6-pp-gcc10-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libubsan1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libubsan1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libubsan1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libubsan1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"gcc10-ada-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libada10-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libada10-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"liblsan0-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"liblsan0-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libquadmath0-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libquadmath0-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libquadmath0-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libquadmath0-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libstdc++6-pp-gcc10-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libtsan0-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libtsan0-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"nvptx-tools-1.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"nvptx-tools-debuginfo-1.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"nvptx-tools-debugsource-1.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"cpp10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"cpp10-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc10-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc10-ada-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc10-ada-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc10-c++-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc10-c++-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc10-c++-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc10-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc10-debugsource-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc10-fortran-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc10-fortran-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc10-fortran-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc10-go-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc10-go-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc10-go-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gcc10-locale-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libada10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libada10-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libasan6-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libasan6-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libasan6-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libasan6-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libatomic1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libatomic1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libatomic1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libatomic1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgcc_s1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgcc_s1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgcc_s1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgcc_s1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgfortran5-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgfortran5-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgfortran5-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgfortran5-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgo16-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgo16-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgo16-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgo16-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgomp1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgomp1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgomp1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgomp1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libitm1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libitm1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libitm1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libitm1-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libstdc++6-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libstdc++6-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libstdc++6-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libstdc++6-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libstdc++6-devel-gcc10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libstdc++6-devel-gcc10-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libstdc++6-locale-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libstdc++6-pp-gcc10-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libubsan1-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libubsan1-32bit-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libubsan1-32bit-debuginfo-10.2.1+git583-1.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libubsan1-debuginfo-10.2.1+git583-1.3.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gcc10 / nvptx-tools");
}
