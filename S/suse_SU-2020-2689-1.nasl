#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:2689-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(143883);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2016-9398", "CVE-2016-9399", "CVE-2017-14132", "CVE-2017-5499", "CVE-2017-5503", "CVE-2017-5504", "CVE-2017-5505", "CVE-2017-9782", "CVE-2018-18873", "CVE-2018-19139", "CVE-2018-19543", "CVE-2018-20570", "CVE-2018-20622", "CVE-2018-9252");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : jasper (SUSE-SU-2020:2689-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for jasper fixes the following issues :

CVE-2016-9398: Improved patch for already fixed issue (bsc#1010979).

CVE-2016-9399: Fix assert in calcstepsizes (bsc#1010980).

CVE-2017-5499: Validate component depth bit (bsc#1020451).

CVE-2017-5503: Check bounds in jas_seq2d_bindsub() (bsc#1020456).

CVE-2017-5504: Check bounds in jas_seq2d_bindsub() (bsc#1020458).

CVE-2017-5505: Check bounds in jas_seq2d_bindsub() (bsc#1020460).

CVE-2017-14132: Fix heap base overflow in by checking components
(bsc#1057152).

CVE-2018-9252: Fix reachable assertion in jpc_abstorelstepsize
(bsc#1088278).

CVE-2018-18873: Fix NULL pointer deref in ras_putdatastd
(bsc#1114498).

CVE-2018-19139: Fix mem leaks by registering jpc_unk_destroyparms
(bsc#1115637).

CVE-2018-19543, bsc#1045450 CVE-2017-9782: Fix numchans mixup
(bsc#1117328).

CVE-2018-20570: Fix heap-based buffer over-read in jp2_encode
(bsc#1120807).

CVE-2018-20622: Fix memory leak in jas_malloc.c (bsc#1120805).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1020451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1020456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1020458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1020460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1088278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1114498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1115637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1117328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1120805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1120807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9398/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9399/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14132/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5499/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5503/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5504/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5505/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9782/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-18873/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19139/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19543/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-20570/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-20622/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-9252/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20202689-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a79158b1"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Packagehub-Subpackages-15-SP1-2020-2689=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Desktop-Applications-15-SP2-2020-2689=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Desktop-Applications-15-SP1-2020-2689=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2020-2689=1

SUSE Linux Enterprise Module for Basesystem 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP1-2020-2689=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:jasper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:jasper-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjasper-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjasper4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjasper4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/21");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1/2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"jasper-2.0.14-3.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"jasper-debuginfo-2.0.14-3.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"jasper-debugsource-2.0.14-3.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libjasper-devel-2.0.14-3.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libjasper4-2.0.14-3.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libjasper4-debuginfo-2.0.14-3.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"jasper-debuginfo-2.0.14-3.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"jasper-debugsource-2.0.14-3.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libjasper-devel-2.0.14-3.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libjasper4-2.0.14-3.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libjasper4-debuginfo-2.0.14-3.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"jasper-2.0.14-3.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"jasper-debuginfo-2.0.14-3.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"jasper-debugsource-2.0.14-3.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libjasper-devel-2.0.14-3.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libjasper4-2.0.14-3.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libjasper4-debuginfo-2.0.14-3.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"jasper-debuginfo-2.0.14-3.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"jasper-debugsource-2.0.14-3.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libjasper-devel-2.0.14-3.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libjasper4-2.0.14-3.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libjasper4-debuginfo-2.0.14-3.16.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jasper");
}
