#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0394-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(133791);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-14250", "CVE-2019-15847");

  script_name(english:"SUSE SLES12 Security Update : gcc9 (SUSE-SU-2020:0394-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for gcc9 fixes the following issues :

The GNU Compiler Collection is shipped in version 9.

A detailed changelog on what changed in GCC 9 is available at
https://gcc.gnu.org/gcc-9/changes.html

The compilers have been added to the SUSE Linux Enterprise Toolchain
Module.

To use these compilers, install e.g. gcc9, gcc9-c++ and build with
CC=gcc-9 CXX=g++-9 set.

For SUSE Linux Enterprise base products, the libstdc++6, libgcc_s1 and
other compiler libraries have been switched from their gcc8 variants
to their gcc9 variants.

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
    value:"https://gcc.gnu.org/gcc-9/changes.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-14250/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-15847/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200394-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71f44a68"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 8:zypper in -t patch
SUSE-OpenStack-Cloud-Crowbar-8-2020-394=1

SUSE OpenStack Cloud 8:zypper in -t patch
SUSE-OpenStack-Cloud-8-2020-394=1

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2020-394=1

SUSE Linux Enterprise Server for SAP 12-SP3:zypper in -t patch
SUSE-SLE-SAP-12-SP3-2020-394=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2020-394=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2020-394=1

SUSE Linux Enterprise Server 12-SP5:zypper in -t patch
SUSE-SLE-SERVER-12-SP5-2020-394=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2020-394=1

SUSE Linux Enterprise Server 12-SP3-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2020-394=1

SUSE Linux Enterprise Server 12-SP3-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-BCL-2020-394=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2020-394=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2020-394=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2020-394=1

SUSE Linux Enterprise Module for Toolchain 12:zypper in -t patch
SUSE-SLE-Module-Toolchain-12-2020-394=1

SUSE Enterprise Storage 5:zypper in -t patch SUSE-Storage-5-2020-394=1

HPE Helion Openstack 8:zypper in -t patch
HPE-Helion-OpenStack-8-2020-394=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc9-debugsource");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtsan0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libubsan1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libubsan1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libubsan1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/19");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(1|2|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1/2/3/4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"liblsan0-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"liblsan0-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libquadmath0-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libquadmath0-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libquadmath0-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libquadmath0-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libtsan0-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libtsan0-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"gcc9-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"gcc9-debugsource-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libasan5-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libasan5-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libasan5-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libasan5-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libatomic1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libatomic1-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libatomic1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libatomic1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgcc_s1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgcc_s1-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgcc_s1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgcc_s1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgfortran5-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgfortran5-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgfortran5-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgfortran5-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgo14-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgo14-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgo14-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgo14-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgomp1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgomp1-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgomp1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgomp1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libitm1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libitm1-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libitm1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libitm1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libstdc++6-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libstdc++6-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libstdc++6-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libstdc++6-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libstdc++6-locale-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libubsan1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libubsan1-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libubsan1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libubsan1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", cpu:"x86_64", reference:"liblsan0-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", cpu:"x86_64", reference:"liblsan0-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", cpu:"x86_64", reference:"libquadmath0-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", cpu:"x86_64", reference:"libquadmath0-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", cpu:"x86_64", reference:"libquadmath0-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", cpu:"x86_64", reference:"libtsan0-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", cpu:"x86_64", reference:"libtsan0-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"gcc9-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"gcc9-debugsource-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libasan5-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libasan5-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libasan5-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libatomic1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libatomic1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libatomic1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgcc_s1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgcc_s1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgcc_s1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgfortran5-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgfortran5-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgfortran5-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgo14-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgo14-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgo14-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgomp1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgomp1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libgomp1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libitm1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libitm1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libitm1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libstdc++6-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libstdc++6-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libstdc++6-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libstdc++6-locale-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libubsan1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libubsan1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libubsan1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"liblsan0-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"liblsan0-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"libquadmath0-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"libquadmath0-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"libquadmath0-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"libquadmath0-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"libtsan0-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"libtsan0-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"gcc9-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"gcc9-debugsource-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libasan5-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libasan5-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libasan5-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libasan5-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libatomic1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libatomic1-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libatomic1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libatomic1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgcc_s1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgcc_s1-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgcc_s1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgcc_s1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgfortran5-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgfortran5-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgfortran5-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgfortran5-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgo14-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgo14-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgo14-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgo14-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgomp1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgomp1-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgomp1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libgomp1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libitm1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libitm1-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libitm1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libitm1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libstdc++6-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libstdc++6-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libstdc++6-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libstdc++6-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libstdc++6-locale-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libubsan1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libubsan1-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libubsan1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libubsan1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"liblsan0-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"liblsan0-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libquadmath0-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libquadmath0-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libquadmath0-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libtsan0-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libtsan0-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"s390x", reference:"libasan5-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"gcc9-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"gcc9-debugsource-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libasan5-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libasan5-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libasan5-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libatomic1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libatomic1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libatomic1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgcc_s1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgcc_s1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgcc_s1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgfortran5-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgfortran5-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgfortran5-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgo14-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgo14-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgo14-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgomp1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgomp1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libgomp1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libitm1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libitm1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libitm1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libstdc++6-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libstdc++6-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libstdc++6-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libstdc++6-locale-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libubsan1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libubsan1-32bit-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libubsan1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libubsan1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"x86_64", reference:"liblsan0-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"x86_64", reference:"liblsan0-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"x86_64", reference:"libquadmath0-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"x86_64", reference:"libquadmath0-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"x86_64", reference:"libquadmath0-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"x86_64", reference:"libtsan0-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"x86_64", reference:"libtsan0-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"gcc9-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"gcc9-debugsource-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libasan5-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libasan5-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libasan5-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libatomic1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libatomic1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libatomic1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgcc_s1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgcc_s1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgcc_s1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgfortran5-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgfortran5-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgfortran5-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgo14-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgo14-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgo14-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgomp1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgomp1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libgomp1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libitm1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libitm1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libitm1-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libstdc++6-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libstdc++6-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libstdc++6-debuginfo-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libstdc++6-locale-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libubsan1-32bit-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libubsan1-9.2.1+r275327-1.3.9")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libubsan1-debuginfo-9.2.1+r275327-1.3.9")) flag++;


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
