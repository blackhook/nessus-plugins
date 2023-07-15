#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:3092-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104783);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-12837", "CVE-2017-12883", "CVE-2017-6512");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : perl (SUSE-SU-2017:3092-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for perl fixes the following issues: Security issues 
fixed :

  - CVE-2017-12837: Heap-based buffer overflow in the
    S_regatom function in regcomp.c in Perl 5 before
    5.24.3-RC1 and 5.26.x before 5.26.1-RC1 allows remote
    attackers to cause a denial of service (out-of-bounds
    write) via a regular expression with a '\N{}' escape and
    the case-insensitive modifier. (bnc#1057724)

  - CVE-2017-12883: Buffer overflow in the S_grok_bslash_N
    function in regcomp.c in Perl 5 before 5.24.3-RC1 and
    5.26.x before 5.26.1-RC1 allows remote attackers to
    disclose sensitive information or cause a denial of
    service (application crash) via a crafted regular
    expression with an invalid '\N{U+...}' escape.
    (bnc#1057721)

  - CVE-2017-6512: Race condition in the rmtree and
    remove_tree functions in the File-Path module before
    2.13 for Perl allows attackers to set the mode on
    arbitrary files via vectors involving
    directory-permission loosening logic. (bnc#1047178) Bug
    fixes :

  - backport set_capture_string changes from upstream
    (bsc#999735)

  - reformat baselibs.conf as source validator workaround

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1047178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=999735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12837/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12883/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6512/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20173092-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74b83522"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-1903=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2017-1903=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-1903=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2017-1903=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-1903=1

SUSE Container as a Service Platform ALL:zypper in -t patch
SUSE-CAASP-ALL-2017-1903=1

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2017-1903=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/27");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-base-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-base-debuginfo-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-debuginfo-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-debugsource-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-32bit-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-debuginfo-32bit-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-base-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-base-debuginfo-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-debuginfo-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-debugsource-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-32bit-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-debuginfo-32bit-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"perl-32bit-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"perl-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"perl-base-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"perl-base-debuginfo-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"perl-debuginfo-32bit-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"perl-debuginfo-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"perl-debugsource-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"perl-32bit-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"perl-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"perl-base-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"perl-base-debuginfo-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"perl-debuginfo-32bit-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"perl-debuginfo-5.18.2-12.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"perl-debugsource-5.18.2-12.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl");
}
