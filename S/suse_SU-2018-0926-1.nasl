#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0926-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(109014);
  script_version("1.4");
  script_cvs_date("Date: 2019/09/10 13:51:47");

  script_cve_id("CVE-2018-1063");

  script_name(english:"SUSE SLES12 Security Update : policycoreutils (SUSE-SU-2018:0926-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for policycoreutils fixes the following issues :

  - CVE-2018-1063: Fixed problem to prevent chcon from
    following symlinks in /tmp, /var/tmp, /var/run and
    /var/lib/debug (bsc#1083624).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1083624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-1063/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180926-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e97b9b7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2018-622=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-622=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-622=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:policycoreutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:policycoreutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:policycoreutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:policycoreutils-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:policycoreutils-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/12");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"policycoreutils-2.5-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"policycoreutils-debuginfo-2.5-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"policycoreutils-debugsource-2.5-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"policycoreutils-python-2.5-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"policycoreutils-python-debuginfo-2.5-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"policycoreutils-2.5-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"policycoreutils-debuginfo-2.5-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"policycoreutils-debugsource-2.5-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"policycoreutils-python-2.5-10.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"policycoreutils-python-debuginfo-2.5-10.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "policycoreutils");
}
