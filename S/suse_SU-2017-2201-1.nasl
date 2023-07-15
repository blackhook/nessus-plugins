#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2201-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102578);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-6435", "CVE-2017-6436", "CVE-2017-6437", "CVE-2017-6438", "CVE-2017-6439");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : libplist (SUSE-SU-2017:2201-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libplist fixes the following issues: Security issues
fixed :

  - CVE-2017-6439: Heap-based buffer overflow in the
    parse_string_node function. (bsc#1029638)

  - CVE-2017-6438: Heap-based buffer overflow in the
    parse_unicode_node function. (bsc#1029706)

  - CVE-2017-6437: The base64encode function in base64.c
    allows local users to cause denial of service
    (out-of-bounds read) via a crafted plist file.
    (bsc#1029707)

  - CVE-2017-6436: Integer overflow in parse_string_node.
    (bsc#1029751)

  - CVE-2017-6435: Crafted plist file could lead to
    Heap-buffer overflow. (bsc#1029639)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1029638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1029639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1029706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1029707"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1029751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6435/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6436/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6437/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6438/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6439/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172201-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b25530be"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP3:zypper in -t patch
SUSE-SLE-WE-12-SP3-2017-1342=1

SUSE Linux Enterprise Workstation Extension 12-SP2:zypper in -t patch
SUSE-SLE-WE-12-SP2-2017-1342=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2017-1342=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-1342=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-1342=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2017-1342=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-1342=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2017-1342=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-1342=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libplist++3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libplist++3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libplist-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libplist3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libplist3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/18");
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
if (rpm_check(release:"SLES12", sp:"3", reference:"libplist-debugsource-1.12-20.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libplist3-1.12-20.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libplist3-debuginfo-1.12-20.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libplist-debugsource-1.12-20.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libplist3-1.12-20.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libplist3-debuginfo-1.12-20.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libplist++3-1.12-20.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libplist++3-debuginfo-1.12-20.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libplist-debugsource-1.12-20.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libplist3-1.12-20.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libplist3-debuginfo-1.12-20.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libplist++3-1.12-20.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libplist++3-debuginfo-1.12-20.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libplist-debugsource-1.12-20.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libplist3-1.12-20.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libplist3-debuginfo-1.12-20.3.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libplist");
}
