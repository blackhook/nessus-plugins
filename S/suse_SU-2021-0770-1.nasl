#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0770-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(147735);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/16");

  script_cve_id("CVE-2017-9271");

  script_name(english:"SUSE SLES15 Security Update : libsolv, libzypp, yast2-installation, zypper (SUSE-SU-2021:0770-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libsolv, libzypp, yast2-installation, zypper fixes the
following issues :

Update zypper to version 1.14.43 :

doc: give more details about creating versioned package locks
(bsc#1181622)

man: Document synonymously used patch categories (bsc#1179847)

Fix source-download commnds help (bsc#1180663)

man: Recommend to use the --non-interactive global option rather than
the command option -y (bsc#1179816)

Extend apt packagemap (fixes #366)

--quiet: Fix install summary to write nothing if there's nothing todo
(bsc#1180077)

Prefer /run over /var/run.

Update libzypp to 17.25.8 :

Try to provide a mounted /proc in --root installs (bsc#1181328) Some
systemd tools require /proc to be mounted and fail if it's not there.

Enable release packages to request a releaxed suse/opensuse
vendorcheck in dup when migrating. (bsc#1182629)

Patch: Identify well-known category names (bsc#1179847) This allows to
use the RH and SUSE patch categrory names synonymously: (recommended =
bugfix) and (optional = feature = enhancement).

Fix %posttrans script execution (fixes #265) The scripts are
execuable. No need to call them through 'sh -c'.

Commit: Fix rpmdb compat symlink in case rpm got removed.

Repo: Allow multiple baseurls specified on one line (fixes #285)

Regex: Fix memory leak and undefined behavior.

Add rpm buildrequires for test suite (fixes #279)

Use rpmdb2solv new -D switch to tell the location ob the rpmdatabase
to use.

BuildRequires: libsolv-devel >= 0.7.17.

CVE-2017-9271: Fixed information leak in the log file (bsc#1050625
bsc#1177583)

RepoManager: Force refresh if repo url has changed (bsc#1174016)

RepoManager: Carefully tidy up the caches. Remove non-directory
entries. (bsc#1178966)

RepoInfo: ignore legacy type= in a .repo file and let RepoManager
probe (bsc#1177427).

RpmDb: If no database exists use the _dbpath configured in rpm. Still
makes sure a compat symlink at /var/lib/rpm exists in case the
configures _dbpath is elsewhere. (bsc#1178910)

Fixed update of gpg keys with elongated expire date (bsc#1179222)

needreboot: remove udev from the list (bsc#1179083)

Fix lsof monitoring (bsc#1179909)

Rephrase solver problem descriptions (jsc#SLE-8482)

Adapt to changed gpg2/libgpgme behavior (bsc#1180721)

Multicurl backend breaks with with unknown filesize (fixes #277)

Update yast2-installation to 4.0.77 :

Do not cleanup the libzypp cache when the system has low memory,
incomplete cache confuses libzypp later (bsc#1179415)

Update libsolv to 0.7.17 :

repo_write: fix handling of nested flexarray

improve choicerule generation a bit more to cover more cases

harden testcase parser against repos being added too late

support python-3.10

check %_dbpath macro in rpmdb code

handle default/visible/langonly attributes in comps parser

support multiple collections in updateinfo parser

add '-D' option in rpmdb2solv to set the dbpath

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1174016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179222"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1181328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1181622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1182629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9271/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210770-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a34c3ca2"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2021-770=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2021-770=1

SUSE Linux Enterprise Installer 15 :

zypper in -t patch SUSE-SLE-INSTALLER-15-2021-770=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2021-770=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2021-770=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:zypper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:zypper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:zypper-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "s390x") audit(AUDIT_ARCH_NOT, "s390x", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libsolv-debuginfo-0.7.17-3.40.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libsolv-debugsource-0.7.17-3.40.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libsolv-devel-0.7.17-3.40.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libsolv-devel-debuginfo-0.7.17-3.40.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libsolv-tools-0.7.17-3.40.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libsolv-tools-debuginfo-0.7.17-3.40.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libzypp-17.25.8-3.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libzypp-debuginfo-17.25.8-3.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libzypp-debugsource-17.25.8-3.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libzypp-devel-17.25.8-3.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"perl-solv-0.7.17-3.40.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"perl-solv-debuginfo-0.7.17-3.40.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"python-solv-0.7.17-3.40.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"python-solv-debuginfo-0.7.17-3.40.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"python3-solv-0.7.17-3.40.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"python3-solv-debuginfo-0.7.17-3.40.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"ruby-solv-0.7.17-3.40.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"ruby-solv-debuginfo-0.7.17-3.40.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"zypper-1.14.43-3.49.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"zypper-debuginfo-1.14.43-3.49.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"zypper-debugsource-1.14.43-3.49.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsolv / libzypp / yast2-installation / zypper");
}
