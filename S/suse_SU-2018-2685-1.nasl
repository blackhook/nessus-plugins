#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2685-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(117452);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2008-1483", "CVE-2016-10012", "CVE-2016-10708", "CVE-2017-15906");
  script_bugtraq_id(28444);

  script_name(english:"SUSE SLES12 Security Update : openssh (SUSE-SU-2018:2685-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for openssh provides the following fixes :

Security issues fixed :

CVE-2017-15906: Stricter checking of operations in read-only mode in
sftp server (bsc#1065000).

CVE-2016-10012: Remove pre-auth compression support from the server to
prevent possible cryptographic attacks (bsc#1016370).

CVE-2008-1483: Refine handling of sockets for X11 forwarding to remove
reintroduced CVE-2008-1483 (bsc#1069509).

CVE-2016-10708: Prevent DoS due to crashes caused by out-of-sequence
NEWKEYS message (bsc#1076957).

Bug fixes: bsc#1017099: Enable case-insensitive hostname matching.

bsc#1023275: Add a new switch for printing diagnostic messages in sftp
client's batch mode.

bsc#1048367: systemd integration to work around various race
conditions.

bsc#1053972: Remove duplicate KEX method.

bsc#1092582: Add missing piece of systemd integration.

Remove the limit on the amount of tasks sshd can run.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1016370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1017099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1023275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1048367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1053972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1065000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1069509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1076957"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1092582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2008-1483/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10012/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10708/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15906/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182685-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a57860a"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2018-1876=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2018-1876=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2018-1876=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-askpass-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-fips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-helpers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-helpers-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/12");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssh-6.6p1-54.15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssh-askpass-gnome-6.6p1-54.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssh-askpass-gnome-debuginfo-6.6p1-54.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssh-debuginfo-6.6p1-54.15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssh-debugsource-6.6p1-54.15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssh-fips-6.6p1-54.15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssh-helpers-6.6p1-54.15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssh-helpers-debuginfo-6.6p1-54.15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssh-6.6p1-54.15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssh-askpass-gnome-6.6p1-54.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssh-askpass-gnome-debuginfo-6.6p1-54.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssh-debuginfo-6.6p1-54.15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssh-debugsource-6.6p1-54.15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssh-fips-6.6p1-54.15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssh-helpers-6.6p1-54.15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssh-helpers-debuginfo-6.6p1-54.15.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh");
}
