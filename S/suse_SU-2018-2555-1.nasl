#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2555-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(112200);
  script_version("1.3");
  script_cvs_date("Date: 2019/09/10 13:51:49");

  script_cve_id("CVE-2017-7435", "CVE-2017-7436", "CVE-2017-9269", "CVE-2018-7685");

  script_name(english:"SUSE SLES12 Security Update : libzypp, zypper (SUSE-SU-2018:2555-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libzypp, zypper provides the following fixes :

libzypp security fixes :

CVE-2018-7685: Validate RPMs before caching (bsc#1091624, bsc#1088705)

CVE-2017-9269: Be sure bad packages do not stay in the cache
(bsc#1045735)

CVE-2017-7435, CVE-2017-7436, CVE-2017-9269: Fix repo gpg check
workflows, mainly for unsigned repos and packages (bsc#1045735,
bsc#1038984)

libzypp changes :

RepoManager: Explicitly request repo2solv to generate application
pseudo packages.

Prefer calling 'repo2solv' rather than 'repo2solv.sh'.

libzypp-devel should not require cmake. (bsc#1101349)

HardLocksFile: Prevent against empty commit without Target having been
loaded. (bsc#1096803)

Avoid zombie tar processes. (bsc#1076192)

man: Make sure that '--config FILE' affects zypper.conf, not
zypp.conf. (bsc#1100028)

ansi.h: Prevent ESC sequence strings from going out of scope.
(bsc#1092413)

RepoInfo: add enum GpgCheck for convenient gpgcheck mode handling
(bsc#1045735)

repo refresh: Re-probe if the repository type changes (bsc#1048315)

Use common workflow for downloading packages and srcpackages. This
includes a common way of handling and reporting gpg signature and
checks. (bsc#1037210)

PackageProvider: as well support downloading SrcPackage (for
bsc#1037210)

Adapt to work with GnuPG 2.1.23 (bsc#1054088) Use 'gpg --list-packets'
to determine the keyid to verify a signature.

Handle http error 502 Bad Gateway in curl backend (bsc#1070851)

zypper security fixes :

Improve signature check callback messages (bsc#1045735, CVE-2017-9269)

add/modify repo: Add options to tune the GPG check settings
(bsc#1045735, CVE-2017-9269)

Adapt download callback to report and handle unsigned packages
(bsc#1038984, CVE-2017-7436)

zypper changes :

download: fix crash when non-package types are passed as argument
(bsc#1037210)

XML <install-summary> attribute `packages-to-change` added
(bsc#1102429) </install-summary>

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1038984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1048315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1054088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1070851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1076192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1088705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1092413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1096803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1100028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1102429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7435/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7436/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9269/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7685/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182555-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a9b69723"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2018-1792=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2018-1792=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:zypper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:zypper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:zypper-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"libzypp-15.25.17-46.22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libzypp-debuginfo-15.25.17-46.22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libzypp-debugsource-15.25.17-46.22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"zypper-1.12.59-46.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"zypper-debuginfo-1.12.59-46.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"zypper-debugsource-1.12.59-46.10.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libzypp / zypper");
}
