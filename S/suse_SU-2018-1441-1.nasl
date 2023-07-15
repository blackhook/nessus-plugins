#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1441-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(110185);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2013-4233", "CVE-2013-4234");
  script_bugtraq_id(61713, 61714);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : libmodplug (SUSE-SU-2018:1441-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libmodplug fixes the following issues :

  - Update to version 0.8.9.0+git20170610.f6dd59a
    bsc#1022032 :

  - PSM: add missing line to commit

  - ABC: prevent possible increment of p past end

  - ABC: ensure read pointer is valid before incrementing

  - ABC: terminate early when things don't work in
    substitute

  - OKT: add one more bound check

  - FAR: out by one on check

  - ABC: 10 digit ints require null termination

  - PSM: make sure reads occur of only valid ins

  - ABC: cleanup tracks correctly.

  - WAV: check that there is space for both headers

  - OKT: ensure file size is enough to contain data

  - ABC: initialize earlier

  - ABC: ensure array access is bounded correctly.

  - ABC: clean up loop exiting code

  - ABC: avoid possibility of incrementing *p

  - ABC: abort early if macro would be blank

  - ABC: Use blankline more often

  - ABC: Ensure for loop does not increment past end of loop

  - Initialize nPatterns to 0 earlier

  - Check memory position isn't over the memory length

  - ABC: transpose only needs to look at notes (

  - Update to version 0.8.9.0+git20171024.e9fc46e :

  - Spelling fixes

  - Bump version number to 0.8.9.0

  - MMCMP: Check that end pointer is within the file size

  - WAV: ensure integer doesn't overflow

  - XM: additional mempos check

  - sndmix: Don't process row if its empty.

  - snd_fx: dont include patterns of zero size in length
    calc

  - MT2,AMF: prevent OOB reads

  - Add patch for broken pc file where quite some upstream
    refer to modplug directly without specifying the subdir
    it is in.

  - Update to version 0.8.8.5

  - Some security issues: CVE-2013-4233, CVE-2013-4234, as
    well as many fixes suggested by static analyzers: clang
    build-scan, and coverity.

  - Stop using dos2unix

  - Run through spec-cleaner

  - Use full URL in Source tag

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1022032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4233/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4234/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181441-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?574d4d71"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-984=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-984=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-984=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmodplug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmodplug1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmodplug1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/29");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"libmodplug-debugsource-0.8.9.0+git20170610.f6dd59a-15.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libmodplug1-0.8.9.0+git20170610.f6dd59a-15.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libmodplug1-debuginfo-0.8.9.0+git20170610.f6dd59a-15.4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libmodplug-debugsource-0.8.9.0+git20170610.f6dd59a-15.4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libmodplug1-0.8.9.0+git20170610.f6dd59a-15.4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libmodplug1-debuginfo-0.8.9.0+git20170610.f6dd59a-15.4.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmodplug");
}
