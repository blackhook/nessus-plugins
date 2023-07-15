#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3901-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(144532);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/15");

  script_cve_id("CVE-2020-16042", "CVE-2020-26971", "CVE-2020-26973", "CVE-2020-26974", "CVE-2020-26978", "CVE-2020-35111", "CVE-2020-35112", "CVE-2020-35113");
  script_xref(name:"IAVA", value:"2020-A-0575-S");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : MozillaFirefox (SUSE-SU-2020:3901-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaFirefox fixes the following issues :

Firefox Extended Support Release 78.6.0 ESR

  - Fixed: Various stability, functionality, and security
    fixes MFSA 2020-55 (bsc#1180039)

  - CVE-2020-16042 (bmo#1679003) Operations on a BigInt
    could have caused uninitialized memory to be exposed

  - CVE-2020-26971 (bmo#1663466) Heap buffer overflow in
    WebGL

  - CVE-2020-26973 (bmo#1680084) CSS Sanitizer performed
    incorrect sanitization

  - CVE-2020-26974 (bmo#1681022) Incorrect cast of
    StyleGenericFlexBasis resulted in a heap use-after-free

  - CVE-2020-26978 (bmo#1677047) Internal network hosts
    could have been probed by a malicious webpage

  - CVE-2020-35111 (bmo#1657916) The proxy.onRequest API did
    not catch view-source URLs

  - CVE-2020-35112 (bmo#1661365) Opening an extension-less
    download may have inadvertently launched an executable
    instead

  - CVE-2020-35113 (bmo#1664831, bmo#1673589) Memory safety
    bugs fixed in Firefox 84 and Firefox ESR 78.6

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1180039"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-16042/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-26971/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-26973/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-26974/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-26978/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-35111/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-35112/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-35113/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203901-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0fc4acd0"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Desktop Applications 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Desktop-Applications-15-SP2-2020-3901=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"2", reference:"MozillaFirefox-78.6.0-8.20.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"MozillaFirefox-debuginfo-78.6.0-8.20.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"MozillaFirefox-debugsource-78.6.0-8.20.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"MozillaFirefox-devel-78.6.0-8.20.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"MozillaFirefox-translations-common-78.6.0-8.20.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"MozillaFirefox-translations-other-78.6.0-8.20.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"MozillaFirefox-78.6.0-8.20.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"MozillaFirefox-debuginfo-78.6.0-8.20.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"MozillaFirefox-debugsource-78.6.0-8.20.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"MozillaFirefox-devel-78.6.0-8.20.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"MozillaFirefox-translations-common-78.6.0-8.20.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"MozillaFirefox-translations-other-78.6.0-8.20.2")) flag++;


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
