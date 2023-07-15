#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2390-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103111);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-1000083");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : evince (SUSE-SU-2017:2390-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for evince fixes the following issue :

  - CVE-2017-1000083: Remote attackers could have used the
    comicbook mode of evince to inject shell code
    (bsc#1046856).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1046856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-1000083/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172390-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb2b206d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP3:zypper in -t patch
SUSE-SLE-WE-12-SP3-2017-1479=1

SUSE Linux Enterprise Workstation Extension 12-SP2:zypper in -t patch
SUSE-SLE-WE-12-SP2-2017-1479=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2017-1479=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-1479=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-1479=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2017-1479=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-1479=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2017-1479=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-1479=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Evince CBT File Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-browser-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-browser-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-djvudocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-djvudocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-dvidocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-dvidocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-pdfdocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-pdfdocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-psdocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-psdocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-tiffdocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-tiffdocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-xpsdocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-xpsdocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libevdocument3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libevdocument3-4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libevview3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libevview3-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nautilus-evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nautilus-evince-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-EvinceDocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-EvinceView");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/11");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"evince-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"evince-browser-plugin-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"evince-browser-plugin-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"evince-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"evince-debugsource-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"evince-plugin-djvudocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"evince-plugin-djvudocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"evince-plugin-dvidocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"evince-plugin-dvidocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"evince-plugin-pdfdocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"evince-plugin-pdfdocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"evince-plugin-psdocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"evince-plugin-psdocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"evince-plugin-tiffdocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"evince-plugin-tiffdocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"evince-plugin-xpsdocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"evince-plugin-xpsdocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libevdocument3-4-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libevdocument3-4-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libevview3-3-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libevview3-3-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"nautilus-evince-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"nautilus-evince-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"evince-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"evince-browser-plugin-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"evince-browser-plugin-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"evince-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"evince-debugsource-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"evince-plugin-djvudocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"evince-plugin-djvudocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"evince-plugin-dvidocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"evince-plugin-dvidocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"evince-plugin-pdfdocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"evince-plugin-pdfdocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"evince-plugin-psdocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"evince-plugin-psdocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"evince-plugin-tiffdocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"evince-plugin-tiffdocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"evince-plugin-xpsdocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"evince-plugin-xpsdocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libevdocument3-4-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libevdocument3-4-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libevview3-3-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libevview3-3-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"nautilus-evince-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"nautilus-evince-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"evince-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"evince-browser-plugin-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"evince-browser-plugin-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"evince-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"evince-debugsource-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"evince-plugin-djvudocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"evince-plugin-djvudocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"evince-plugin-dvidocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"evince-plugin-dvidocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"evince-plugin-pdfdocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"evince-plugin-pdfdocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"evince-plugin-psdocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"evince-plugin-psdocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"evince-plugin-tiffdocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"evince-plugin-tiffdocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"evince-plugin-xpsdocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"evince-plugin-xpsdocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libevdocument3-4-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libevdocument3-4-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libevview3-3-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libevview3-3-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"nautilus-evince-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"nautilus-evince-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"typelib-1_0-EvinceDocument-3_0-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"typelib-1_0-EvinceView-3_0-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"evince-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"evince-browser-plugin-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"evince-browser-plugin-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"evince-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"evince-debugsource-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"evince-plugin-djvudocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"evince-plugin-djvudocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"evince-plugin-dvidocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"evince-plugin-dvidocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"evince-plugin-pdfdocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"evince-plugin-pdfdocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"evince-plugin-psdocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"evince-plugin-psdocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"evince-plugin-tiffdocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"evince-plugin-tiffdocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"evince-plugin-xpsdocument-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"evince-plugin-xpsdocument-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libevdocument3-4-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libevdocument3-4-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libevview3-3-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libevview3-3-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"nautilus-evince-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"nautilus-evince-debuginfo-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"typelib-1_0-EvinceDocument-3_0-3.20.1-6.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"typelib-1_0-EvinceView-3_0-3.20.1-6.16.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evince");
}
