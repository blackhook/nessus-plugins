#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2933-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104428);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2016-7586", "CVE-2016-7589", "CVE-2016-7592", "CVE-2016-7599", "CVE-2016-7623", "CVE-2016-7632", "CVE-2016-7635", "CVE-2016-7639", "CVE-2016-7641", "CVE-2016-7645", "CVE-2016-7652", "CVE-2016-7654", "CVE-2016-7656", "CVE-2017-2350", "CVE-2017-2354", "CVE-2017-2355", "CVE-2017-2356", "CVE-2017-2362", "CVE-2017-2363", "CVE-2017-2364", "CVE-2017-2365", "CVE-2017-2366", "CVE-2017-2369", "CVE-2017-2371", "CVE-2017-2373", "CVE-2017-2496", "CVE-2017-2510", "CVE-2017-2538", "CVE-2017-2539", "CVE-2017-7018", "CVE-2017-7030", "CVE-2017-7034", "CVE-2017-7037", "CVE-2017-7039", "CVE-2017-7046", "CVE-2017-7048", "CVE-2017-7055", "CVE-2017-7056", "CVE-2017-7061", "CVE-2017-7064");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : webkit2gtk3 (SUSE-SU-2017:2933-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for webkit2gtk3 to version 2.18.0 fixes the following
issues: These security issues were fixed :

  - CVE-2017-7039: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1050469).

  - CVE-2017-7018: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1050469).

  - CVE-2017-7030: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1050469).

  - CVE-2017-7037: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1050469).

  - CVE-2017-7034: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1050469).

  - CVE-2017-7055: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1050469).

  - CVE-2017-7056: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1050469).

  - CVE-2017-7064: An issue was fixed that allowed remote
    attackers to bypass intended memory-read restrictions
    via a crafted app (bsc#1050469).

  - CVE-2017-7061: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1050469).

  - CVE-2017-7048: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1050469).

  - CVE-2017-7046: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1050469).

  - CVE-2017-2538: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1045460)

  - CVE-2017-2496: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website.

  - CVE-2017-2539: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website.

  - CVE-2017-2510: An issue was fixed that allowed remote
    attackers to conduct Universal XSS (UXSS) attacks via a
    crafted website that improperly interacts with pageshow
    events.

  - CVE-2017-2365: An issue was fixed that allowed remote
    attackers to bypass the Same Origin Policy and obtain
    sensitive information via a crafted website
    (bsc#1024749)

  - CVE-2017-2366: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1024749)

  - CVE-2017-2373: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1024749)

  - CVE-2017-2363: An issue was fixed that allowed remote
    attackers to bypass the Same Origin Policy and obtain
    sensitive information via a crafted website
    (bsc#1024749)

  - CVE-2017-2362: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1024749)

  - CVE-2017-2350: An issue was fixed that allowed remote
    attackers to bypass the Same Origin Policy and obtain
    sensitive information via a crafted website
    (bsc#1024749)

  - CVE-2017-2350: An issue was fixed that allowed remote
    attackers to bypass the Same Origin Policy and obtain
    sensitive information via a crafted website
    (bsc#1024749)

  - CVE-2017-2354: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1024749).

  - CVE-2017-2355: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (uninitialized memory access and application
    crash) via a crafted website (bsc#1024749)

  - CVE-2017-2356: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1024749)

  - CVE-2017-2371: An issue was fixed that allowed remote
    attackers to launch popups via a crafted website
    (bsc#1024749)

  - CVE-2017-2364: An issue was fixed that allowed remote
    attackers to bypass the Same Origin Policy and obtain
    sensitive information via a crafted website
    (bsc#1024749)

  - CVE-2017-2369: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1024749)

  - CVE-2016-7656: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1020950)

  - CVE-2016-7635: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1020950)

  - CVE-2016-7654: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1020950)

  - CVE-2016-7639: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1020950)

  - CVE-2016-7645: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1020950)

  - CVE-2016-7652: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1020950)

  - CVE-2016-7641: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1020950)

  - CVE-2016-7632: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1020950)

  - CVE-2016-7599: An issue was fixed that allowed remote
    attackers to bypass the Same Origin Policy and obtain
    sensitive information via a crafted website that used
    HTTP redirects (bsc#1020950)

  - CVE-2016-7592: An issue was fixed that allowed remote
    attackers to obtain sensitive information via crafted
    JavaScript prompts on a web site (bsc#1020950)

  - CVE-2016-7589: An issue was fixed that allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1020950)

  - CVE-2016-7623: An issue was fixed that allowed remote
    attackers to obtain sensitive information via a blob URL
    on a website (bsc#1020950)

  - CVE-2016-7586: An issue was fixed that allowed remote
    attackers to obtain sensitive information via a crafted
    website (bsc#1020950) For other non-security fixes
    please check the changelog.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1020950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1024749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7586/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7589/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7592/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7599/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7623/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7632/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7635/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7639/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7641/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7645/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7652/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7654/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7656/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2350/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2354/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2355/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2356/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2362/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2363/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2364/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2365/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2366/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2369/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2371/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2373/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2496/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2510/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2538/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2539/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7018/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7030/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7034/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7037/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7039/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7046/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7048/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7055/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7056/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7061/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7064/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172933-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f9052a2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP3:zypper in -t patch
SUSE-SLE-WE-12-SP3-2017-1815=1

SUSE Linux Enterprise Workstation Extension 12-SP2:zypper in -t patch
SUSE-SLE-WE-12-SP2-2017-1815=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2017-1815=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-1815=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-1815=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2017-1815=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-1815=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2017-1815=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-1815=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjavascriptcoregtk-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjavascriptcoregtk-4_0-18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebkit2gtk-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebkit2gtk-4_0-37-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-JavaScriptCore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk-4_0-injected-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk-4_0-injected-bundles-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk3-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/07");
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
if (rpm_check(release:"SLES12", sp:"3", reference:"libjavascriptcoregtk-4_0-18-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwebkit2gtk-4_0-37-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwebkit2gtk-4_0-37-debuginfo-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"typelib-1_0-JavaScriptCore-4_0-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"typelib-1_0-WebKit2-4_0-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"webkit2gtk-4_0-injected-bundles-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"webkit2gtk3-debugsource-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libjavascriptcoregtk-4_0-18-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libwebkit2gtk-4_0-37-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libwebkit2gtk-4_0-37-debuginfo-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"typelib-1_0-JavaScriptCore-4_0-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"typelib-1_0-WebKit2-4_0-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"webkit2gtk-4_0-injected-bundles-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"webkit2gtk3-debugsource-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-debuginfo-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"typelib-1_0-JavaScriptCore-4_0-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"typelib-1_0-WebKit2-4_0-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"webkit2gtk-4_0-injected-bundles-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"webkit2gtk3-debugsource-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-debuginfo-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"typelib-1_0-JavaScriptCore-4_0-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"typelib-1_0-WebKit2-4_0-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"webkit2gtk-4_0-injected-bundles-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.18.0-2.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"webkit2gtk3-debugsource-2.18.0-2.9.1")) flag++;


if (flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "webkit2gtk3");
}
