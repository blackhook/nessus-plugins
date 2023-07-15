#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3476-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(120146);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/16");

  script_cve_id("CVE-2018-12383", "CVE-2018-12385", "CVE-2018-12386", "CVE-2018-12387");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : MozillaFirefox (SUSE-SU-2018:3476-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaFirefox to 60.2.2ESR fixes the following 
issues :

Security issues fixed :

MFSA 2018-24 :

CVE-2018-12386: A Type confusion in JavaScript allowed remote code
execution (bsc#1110506)

CVE-2018-12387: Array.prototype.push stack pointer vulnerability may
have enabled exploits in the sandboxed content process (bsc#1110507)

MFSA 2018-23: CVE-2018-12385: Fixed a crash in TransportSecurityInfo
due to cached data (bsc#1109363)

CVE-2018-12383: Setting a master password did not delete unencrypted
previously stored passwords (bsc#1107343)

Non security issues fixed: Avoid undefined behavior in IPC fd-passing
code (bsc#1094767)

Fixed a startup crash affecting users migrating from older ESR
releases

Clean up old NSS DB files after upgrading

Fixed an endianness problem in bindgen's handling of bitfields, which
was causing Firefox to crash on startup on big-endian machines. Also,
updates the cc crate, which was buggy in the version that was
originally vendored in. (bsc#1109465)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1094767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1109363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1109465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1110506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1110507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12383/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12385/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12386/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12387/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183476-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8bc9d855"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2018-2482=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-SLE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"MozillaFirefox-devel-60.2.2-3.13.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-60.2.2-3.13.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-branding-SLE-60-4.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-debuginfo-60.2.2-3.13.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-debugsource-60.2.2-3.13.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-translations-common-60.2.2-3.13.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-translations-other-60.2.2-3.13.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"MozillaFirefox-devel-60.2.2-3.13.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-60.2.2-3.13.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-branding-SLE-60-4.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-debuginfo-60.2.2-3.13.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-debugsource-60.2.2-3.13.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-translations-common-60.2.2-3.13.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-translations-other-60.2.2-3.13.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
