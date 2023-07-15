#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2941-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(130945);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-9893");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : libseccomp (SUSE-SU-2019:2941-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libseccomp fixes the following issues :

Update to new upstream release 2.4.1 :

Fix a BPF generation bug where the optimizer mistakenly identified
duplicate BPF code blocks.

Updated to 2.4.0 (bsc#1128828 CVE-2019-9893): Update the syscall table
for Linux v5.0-rc5

Added support for the SCMP_ACT_KILL_PROCESS action

Added support for the SCMP_ACT_LOG action and SCMP_FLTATR_CTL_LOG
attribute

Added explicit 32-bit (SCMP_AX_32(...)) and 64-bit (SCMP_AX_64(...))
argument comparison macros to help protect against unexpected sign
extension

Added support for the parisc and parisc64 architectures

Added the ability to query and set the libseccomp API level via
seccomp_api_get(3) and seccomp_api_set(3)

Return -EDOM on an endian mismatch when adding an architecture to a
filter

Renumber the pseudo syscall number for subpage_prot() so it no longer
conflicts with spu_run()

Fix PFC generation when a syscall is prioritized, but no rule exists

Numerous fixes to the seccomp-bpf filter generation code

Switch our internal hashing function to jhash/Lookup3 to MurmurHash3

Numerous tests added to the included test suite, coverage now at ~92%

Update our Travis CI configuration to use Ubuntu 16.04

Numerous documentation fixes and updates

Update to release 2.3.3: Updated the syscall table for Linux v4.15-rc7

Update to release 2.3.2: Achieved full compliance with the CII Best
Practices program

Added Travis CI builds to the GitHub repository

Added code coverage reporting with the '--enable-code-coverage'
configure flag and added Coveralls to the GitHub repository

Updated the syscall tables to match Linux v4.10-rc6+

Support for building with Python v3.x

Allow rules with the -1 syscall if the SCMP\_FLTATR\_API\_TSKIP
attribute is set to true

Several small documentation fixes

ignore make check error for ppc64/ppc64le, bypass bsc#1142614

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1082318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1128828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1142614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-9893/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192941-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eb11b7d2"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 8:zypper in -t patch
SUSE-OpenStack-Cloud-Crowbar-8-2019-2941=1

SUSE OpenStack Cloud 8:zypper in -t patch
SUSE-OpenStack-Cloud-8-2019-2941=1

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2019-2941=1

SUSE Linux Enterprise Software Development Kit 12-SP5:zypper in -t
patch SUSE-SLE-SDK-12-SP5-2019-2941=1

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2019-2941=1

SUSE Linux Enterprise Server for SAP 12-SP3:zypper in -t patch
SUSE-SLE-SAP-12-SP3-2019-2941=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2019-2941=1

SUSE Linux Enterprise Server 12-SP5:zypper in -t patch
SUSE-SLE-SERVER-12-SP5-2019-2941=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-2941=1

SUSE Linux Enterprise Server 12-SP3-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2019-2941=1

SUSE Linux Enterprise Server 12-SP3-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-BCL-2019-2941=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2019-2941=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2019-2941=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-2941=1

SUSE Enterprise Storage 5:zypper in -t patch
SUSE-Storage-5-2019-2941=1

SUSE CaaS Platform 3.0 :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

HPE Helion Openstack 8:zypper in -t patch
HPE-Helion-OpenStack-8-2019-2941=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libseccomp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libseccomp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libseccomp2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/13");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4/5", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"libseccomp-debugsource-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libseccomp2-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libseccomp2-32bit-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libseccomp2-debuginfo-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libseccomp2-debuginfo-32bit-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libseccomp-debugsource-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libseccomp2-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libseccomp2-32bit-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libseccomp2-debuginfo-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libseccomp2-debuginfo-32bit-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libseccomp-debugsource-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libseccomp2-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libseccomp2-32bit-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libseccomp2-debuginfo-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libseccomp2-debuginfo-32bit-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libseccomp-debugsource-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libseccomp2-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libseccomp2-32bit-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libseccomp2-debuginfo-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libseccomp2-debuginfo-32bit-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libseccomp-debugsource-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libseccomp2-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libseccomp2-32bit-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libseccomp2-debuginfo-2.4.1-11.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libseccomp2-debuginfo-32bit-2.4.1-11.3.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libseccomp");
}
