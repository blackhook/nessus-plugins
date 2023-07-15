#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0109-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(144960);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/20");

  script_cve_id("CVE-2017-9271");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : libzypp, zypper (SUSE-SU-2021:0109-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libzypp, zypper fixes the following issues :

Update zypper to version 1.14.41

Update libzypp to 17.25.4

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

Fixed update of gpg keys with elongated expire date (bsc#179222)

needreboot: remove udev from the list (bsc#1179083)

Fix lsof monitoring (bsc#1179909)

yast-installation was updated to 4.2.48 :

Do not cleanup the libzypp cache when the system has low memory,
incomplete cache confuses libzypp later (bsc#1179415)

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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9271/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210109-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a146392c"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2021-109=1

SUSE Linux Enterprise Installer 15-SP2 :

zypper in -t patch SUSE-SLE-INSTALLER-15-SP2-2021-109=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:zypper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:zypper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:zypper-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"2", reference:"libzypp-17.25.5-3.25.6")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libzypp-debuginfo-17.25.5-3.25.6")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libzypp-debugsource-17.25.5-3.25.6")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libzypp-devel-17.25.5-3.25.6")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"zypper-1.14.41-3.14.10")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"zypper-debuginfo-1.14.41-3.14.10")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"zypper-debugsource-1.14.41-3.14.10")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libzypp-17.25.5-3.25.6")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libzypp-debuginfo-17.25.5-3.25.6")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libzypp-debugsource-17.25.5-3.25.6")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libzypp-devel-17.25.5-3.25.6")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"zypper-1.14.41-3.14.10")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"zypper-debuginfo-1.14.41-3.14.10")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"zypper-debugsource-1.14.41-3.14.10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libzypp / zypper");
}
