#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:1724-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83655);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-3636", "CVE-2014-7824");
  script_bugtraq_id(69834, 71012);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : dbus-1 (SUSE-SU-2014:1724-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"dbus-1 was updated to version 1.8.12 to fix one security issue.

This security issue was fixed :

  - Increase dbus-daemons RLIMIT_NOFILE rlimit to 65536 to
    stop an attacker from exhausting the file descriptors of
    the system bus (CVE-2014-7824).

Note: This already includes the fix for the regression that was
introduced by the first fix for CVE-2014-7824 in 1.8.10.

On fast systems where local users are considered particularly hostile,
administrators can return to the 5 second timeout (or any other value
in milliseconds) by saving this as /etc/dbus-1/system-local.conf:
<busconfig> <limit name='auth_timeout'>5000</limit> </busconfig>

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=904017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3636/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-7824/"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20141724-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4417f330"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2014-121

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2014-121

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2014-121

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dbus-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dbus-1-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dbus-1-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dbus-1-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dbus-1-x11-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdbus-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdbus-1-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdbus-1-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"dbus-1-1.8.12-6.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"dbus-1-debuginfo-1.8.12-6.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"dbus-1-debugsource-1.8.12-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"dbus-1-x11-1.8.12-6.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"dbus-1-x11-debuginfo-1.8.12-6.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"dbus-1-x11-debugsource-1.8.12-6.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdbus-1-3-1.8.12-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdbus-1-3-debuginfo-1.8.12-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdbus-1-3-32bit-1.8.12-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdbus-1-3-debuginfo-32bit-1.8.12-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"dbus-1-1.8.12-6.5")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"dbus-1-debuginfo-1.8.12-6.5")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"dbus-1-debugsource-1.8.12-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"dbus-1-x11-1.8.12-6.5")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"dbus-1-x11-debuginfo-1.8.12-6.5")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"dbus-1-x11-debugsource-1.8.12-6.5")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libdbus-1-3-1.8.12-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libdbus-1-3-32bit-1.8.12-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libdbus-1-3-debuginfo-1.8.12-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libdbus-1-3-debuginfo-32bit-1.8.12-6.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dbus-1");
}
