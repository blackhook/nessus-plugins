#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1373-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85377);
  script_version("2.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2015-3107", "CVE-2015-5124", "CVE-2015-5125", "CVE-2015-5127", "CVE-2015-5128", "CVE-2015-5129", "CVE-2015-5130", "CVE-2015-5131", "CVE-2015-5132", "CVE-2015-5133", "CVE-2015-5134", "CVE-2015-5539", "CVE-2015-5540", "CVE-2015-5541", "CVE-2015-5544", "CVE-2015-5545", "CVE-2015-5546", "CVE-2015-5547", "CVE-2015-5548", "CVE-2015-5549", "CVE-2015-5550", "CVE-2015-5551", "CVE-2015-5552", "CVE-2015-5553", "CVE-2015-5554", "CVE-2015-5555", "CVE-2015-5556", "CVE-2015-5557", "CVE-2015-5558", "CVE-2015-5559", "CVE-2015-5560", "CVE-2015-5561", "CVE-2015-5562", "CVE-2015-5563");
  script_bugtraq_id(75087, 75959);

  script_name(english:"SUSE SLED11 Security Update : flash-player (SUSE-SU-2015:1373-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This security update to 11.2.202.508 (bsc#941239) fixes the following
issues :

  - APSB15-19: CVE-2015-3107, CVE-2015-5124, CVE-2015-5125,
    CVE-2015-5127, CVE-2015-5128, CVE-2015-5129,
    CVE-2015-5130, CVE-2015-5131, CVE-2015-5132,
    CVE-2015-5133, CVE-2015-5134, CVE-2015-5539,
    CVE-2015-5540, CVE-2015-5541, CVE-2015-5544,
    CVE-2015-5545, CVE-2015-5546, CVE-2015-5547,
    CVE-2015-5548, CVE-2015-5549, CVE-2015-5550,
    CVE-2015-5551, CVE-2015-5552, CVE-2015-5553,
    CVE-2015-5554, CVE-2015-5555, CVE-2015-5556,
    CVE-2015-5557, CVE-2015-5558, CVE-2015-5559,
    CVE-2015-5560, CVE-2015-5561, CVE-2015-5562,
    CVE-2015-5563

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=941239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3107/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5124/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5125/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5127/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5128/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5129/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5130/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5131/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5132/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5133/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5134/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5539/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5540/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5541/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5544/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5545/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5546/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5547/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5548/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5549/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5550/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5551/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5552/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5553/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5554/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5555/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5556/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5557/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5558/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5559/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5560/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5561/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5562/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5563/"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151373-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?243a9f3c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-flash-player-12025=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-flash-player-12025=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flash-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flash-player-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flash-player-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/13");
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
if (! preg(pattern:"^(SLED11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"flash-player-11.2.202.508-0.14.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"flash-player-gnome-11.2.202.508-0.14.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"flash-player-kde4-11.2.202.508-0.14.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"flash-player-11.2.202.508-0.14.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"flash-player-gnome-11.2.202.508-0.14.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"flash-player-kde4-11.2.202.508-0.14.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"flash-player-11.2.202.508-0.14.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"flash-player-gnome-11.2.202.508-0.14.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"flash-player-kde4-11.2.202.508-0.14.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"flash-player-11.2.202.508-0.14.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"flash-player-gnome-11.2.202.508-0.14.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"flash-player-kde4-11.2.202.508-0.14.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flash-player");
}
