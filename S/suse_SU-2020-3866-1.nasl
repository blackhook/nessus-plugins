#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3866-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(144445);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2020-14145");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : openssh (SUSE-SU-2020:3866-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for openssh fixes the following issues :

CVE-2020-14145: Fixed a potential information leak during host key
exchange (bsc#1173513).

Supplement libgtk-3-0 instead of libX11-6 to avoid installation on a
textmode install (bsc#1142000)

Fixed an issue where oracle cluster with cluvfy using 'scp'
failing/missinterpreted (bsc#1148566).

Fixed sshd termination of multichannel sessions with non-root users
(bsc#1115550,bsc#1174162).

Added speculative hardening for key storage (bsc#1139398).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1115550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1139398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1142000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1148566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1173513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1174162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-14145/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203866-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0de09e9d"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Server-Applications-15-SP1-2020-3866=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Desktop-Applications-15-SP1-2020-3866=1

SUSE Linux Enterprise Module for Basesystem 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP1-2020-3866=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-askpass-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-askpass-gnome-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-fips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-helpers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-helpers-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/18");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"openssh-7.9p1-6.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"openssh-askpass-gnome-7.9p1-6.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"openssh-askpass-gnome-debuginfo-7.9p1-6.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"openssh-askpass-gnome-debugsource-7.9p1-6.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"openssh-debuginfo-7.9p1-6.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"openssh-debugsource-7.9p1-6.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"openssh-fips-7.9p1-6.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"openssh-helpers-7.9p1-6.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"openssh-helpers-debuginfo-7.9p1-6.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"openssh-7.9p1-6.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"openssh-askpass-gnome-7.9p1-6.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"openssh-askpass-gnome-debuginfo-7.9p1-6.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"openssh-askpass-gnome-debugsource-7.9p1-6.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"openssh-debuginfo-7.9p1-6.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"openssh-debugsource-7.9p1-6.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"openssh-helpers-7.9p1-6.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"openssh-helpers-debuginfo-7.9p1-6.22.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh");
}
