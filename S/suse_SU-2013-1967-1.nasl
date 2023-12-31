#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2013:1967-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83605);
  script_version("2.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"SUSE SLED11 Security Update : acroread (SUSE-SU-2013:1967-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Adobe has discontinued the support of Adobe Reader for Linux in June
2013.

Newer security problems and bugs are no longer fixed.

As the Adobe Reader is binary only software and we cannot provide a
replacement, SUSE declares the acroread package of Adobe Reader as
being out of support and unmaintained.

If you do not need Acrobat Reader, we recommend to uninstall the
'acroread' package.

This update removes the Acrobat Reader PDF plugin to avoid automatic
exploitation by clicking on web pages with embedded PDFs.

The stand alone 'acroread' binary is still available, but again, we do
not recommend to use it.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=1ba40421128e83afa47923da7fa45a4e
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13e5cce2"
  );
  # http://download.suse.com/patch/finder/?keywords=622bc5e164e4f99a6b0b90dded3112a4
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f88a90b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/843835"
  );
  # https://www.suse.com/support/update/announcement/2013/suse-su-20131967-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad285f04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Desktop 11 SP3 :

zypper in -t patch sledsp3-acroread-8689

SUSE Linux Enterprise Desktop 11 SP2 :

zypper in -t patch sledsp2-acroread-8688

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:acroread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:acroread_ja");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");
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
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED11" && (! ereg(pattern:"^3|2$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"acroread-9.5.5-0.5.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"acroread-9.5.5-0.5.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"acroread-9.5.5-0.5.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"acroread_ja-9.4.2-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"acroread-9.5.5-0.5.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"acroread_ja-9.4.2-0.4.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "acroread");
}
