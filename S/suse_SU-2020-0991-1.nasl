#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0991-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(135579);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2020-5260");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : git (SUSE-SU-2020:0991-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for git fixes the following issues :

CVE-2020-5260: With a crafted URL that contains a newline in it, the
credential helper machinery can be fooled to give credential
information for a wrong host (bsc#1168930).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1168930"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-5260/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200991-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0289361a"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15:zypper in -t patch
SUSE-SLE-Product-SLES_SAP-15-2020-991=1

SUSE Linux Enterprise Server 15-LTSS:zypper in -t patch
SUSE-SLE-Product-SLES-15-2020-991=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-991=1

SUSE Linux Enterprise Module for Development Tools 15-SP1:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-SP1-2020-991=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2020-991=1

SUSE Linux Enterprise High Performance Computing 15-LTSS:zypper in -t
patch SUSE-SLE-Product-HPC-15-2020-991=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS:zypper in -t
patch SUSE-SLE-Product-HPC-15-2020-991=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5260");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-arch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-credential-gnome-keyring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-credential-gnome-keyring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-credential-libsecret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-credential-libsecret-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-svn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gitk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/15");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-arch-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-core-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-core-debuginfo-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-credential-gnome-keyring-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-credential-gnome-keyring-debuginfo-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-credential-libsecret-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-credential-libsecret-debuginfo-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-cvs-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-daemon-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-daemon-debuginfo-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-debuginfo-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-debugsource-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-email-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-gui-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-p4-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-svn-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-svn-debuginfo-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-web-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gitk-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"git-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"git-arch-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"git-core-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"git-core-debuginfo-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"git-cvs-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"git-daemon-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"git-daemon-debuginfo-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"git-debuginfo-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"git-debugsource-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"git-email-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"git-gui-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"git-svn-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"git-svn-debuginfo-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"git-web-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gitk-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-arch-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-core-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-core-debuginfo-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-credential-gnome-keyring-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-credential-gnome-keyring-debuginfo-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-credential-libsecret-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-credential-libsecret-debuginfo-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-cvs-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-daemon-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-daemon-debuginfo-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-debuginfo-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-debugsource-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-email-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-gui-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-p4-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-svn-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-svn-debuginfo-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-web-2.16.4-3.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gitk-2.16.4-3.20.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "git");
}
