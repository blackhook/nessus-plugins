#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2529-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103369);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-14482");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : emacs (SUSE-SU-2017:2529-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for emacs fixes one issues. This security issue was 
fixed :

  - CVE-2017-14482: Remote code execution via mails with
    'Content-Type: text/enriched' (bsc#1058425)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1058425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14482/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172529-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82add21c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 6:zypper in -t patch
SUSE-OpenStack-Cloud-6-2017-1565=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2017-1565=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-1565=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2017-1565=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-1565=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2017-1565=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2017-1565=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2017-1565=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-1565=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:emacs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:emacs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:emacs-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:emacs-nox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:emacs-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:emacs-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:etags");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:etags-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/21");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(0|1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1/2/3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"emacs-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"emacs-debuginfo-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"emacs-debugsource-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"emacs-nox-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"emacs-nox-debuginfo-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"emacs-x11-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"emacs-x11-debuginfo-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"etags-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"etags-debuginfo-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"emacs-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"emacs-debuginfo-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"emacs-debugsource-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"emacs-nox-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"emacs-nox-debuginfo-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"emacs-x11-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"emacs-x11-debuginfo-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"etags-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"etags-debuginfo-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"emacs-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"emacs-debuginfo-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"emacs-debugsource-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"emacs-nox-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"emacs-nox-debuginfo-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"emacs-x11-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"emacs-x11-debuginfo-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"etags-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"etags-debuginfo-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"emacs-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"emacs-debuginfo-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"emacs-debugsource-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"emacs-nox-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"emacs-nox-debuginfo-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"emacs-x11-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"emacs-x11-debuginfo-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"etags-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"etags-debuginfo-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"emacs-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"emacs-debuginfo-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"emacs-debugsource-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"emacs-x11-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"emacs-x11-debuginfo-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"etags-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"etags-debuginfo-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"emacs-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"emacs-debuginfo-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"emacs-debugsource-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"emacs-x11-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"emacs-x11-debuginfo-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"etags-24.3-25.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"etags-debuginfo-24.3-25.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs");
}
