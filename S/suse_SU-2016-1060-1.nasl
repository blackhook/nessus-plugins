#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1060-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90585);
  script_version("2.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2016-1651", "CVE-2016-1652", "CVE-2016-1653", "CVE-2016-1654", "CVE-2016-1655", "CVE-2016-1656", "CVE-2016-1657", "CVE-2016-1658", "CVE-2016-1659");

  script_name(english:"SUSE SLES12 Security Update : Chromium (SUSE-SU-2016:1060-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Chromium was updated to 50.0.2661.75 to fix the following
vulnerabilities :

  - CVE-2016-1651: Out-of-bounds read in Pdfium JPEG2000
    decoding

  - CVE-2016-1652: Universal XSS in extension bindings

  - CVE-2016-1653: Out-of-bounds write in V8

  - CVE-2016-1654: Uninitialized memory read in media

  - CVE-2016-1655: Use-after-free related to extensions

  - CVE-2016-1656: Android downloaded file path restriction
    bypass

  - CVE-2016-1657: Address bar spoofing

  - CVE-2016-1658: Potential leak of sensitive information
    to malicious extensions

  - CVE-2016-1659: Various fixes from internal audits,
    fuzzing and other initiatives

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=975572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1651/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1652/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1653/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1654/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1655/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1656/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1657/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1658/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1659/"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161060-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9a0cc2bc"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Package Hub for SUSE Linux Enterprise 12 :

zypper in -t patch 4965=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:chromium-desktop-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:chromium-desktop-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:chromium-ffmpegsumo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:chromium-ffmpegsumo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"chromedriver-50.0.2661.75-68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"chromedriver-debuginfo-50.0.2661.75-68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"chromium-50.0.2661.75-68.1", allowmaj:TRUE)) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"chromium-debuginfo-50.0.2661.75-68.1", allowmaj:TRUE)) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"chromium-debugsource-50.0.2661.75-68.1", allowmaj:TRUE)) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"chromium-desktop-gnome-50.0.2661.75-68.1", allowmaj:TRUE)) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"chromium-desktop-kde-50.0.2661.75-68.1", allowmaj:TRUE)) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"chromium-ffmpegsumo-50.0.2661.75-68.1", allowmaj:TRUE)) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"chromium-ffmpegsumo-debuginfo-50.0.2661.75-68.1", allowmaj:TRUE)) flag++;


if (flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Chromium");
}
