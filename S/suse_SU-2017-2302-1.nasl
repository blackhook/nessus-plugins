#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2302-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102856);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-7753", "CVE-2017-7779", "CVE-2017-7782", "CVE-2017-7784", "CVE-2017-7785", "CVE-2017-7786", "CVE-2017-7787", "CVE-2017-7791", "CVE-2017-7792", "CVE-2017-7798", "CVE-2017-7800", "CVE-2017-7801", "CVE-2017-7802", "CVE-2017-7803", "CVE-2017-7804", "CVE-2017-7807");

  script_name(english:"SUSE SLES11 Security Update : MozillaFirefox (SUSE-SU-2017:2302-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to the ESR 52.3 release (bsc#1052829)
Following security issues were fixed :

  - MFSA 2017-19/CVE-2017-7807: Domain hijacking through
    AppCache fallback

  - MFSA 2017-19/CVE-2017-7791: Spoofing following page
    navigation with data: protocol and modal alerts

  - MFSA 2017-19/CVE-2017-7792: Buffer overflow viewing
    certificates with an extremely long OID

  - MFSA 2017-19/CVE-2017-7782: WindowsDllDetourPatcher
    allocates memory without DEP protections

  - MFSA 2017-19/CVE-2017-7787: Same-origin policy bypass
    with iframes through page reloads

  - MFSA 2017-19/CVE-2017-7786: Buffer overflow while
    painting non-displayable SVG

  - MFSA 2017-19/CVE-2017-7785: Buffer overflow manipulating
    ARIA attributes in DOM

  - MFSA 2017-19/CVE-2017-7784: Use-after-free with image
    observers

  - MFSA 2017-19/CVE-2017-7753: Out-of-bounds read with
    cached style data and pseudo-elements

  - MFSA 2017-19/CVE-2017-7798: XUL injection in the style
    editor in devtools

  - MFSA 2017-19/CVE-2017-7804: Memory protection bypass
    through WindowsDllDetourPatcher

  - MFSA 2017-19/CVE-2017-7779: Memory safety bugs fixed in
    Firefox 55 and Firefox ESR 52.3

  - MFSA 2017-19/CVE-2017-7800: Use-after-free in WebSockets
    during disconnection

  - MFSA 2017-19/CVE-2017-7801: Use-after-free with marquee
    during window resizing

  - MFSA 2017-19/CVE-2017-7802: Use-after-free resizing
    image elements

  - MFSA 2017-19/CVE-2017-7803: CSP containing 'sandbox'
    improperly applied This update also fixes :

  - fixed firefox hangs after a while in FUTEX_WAIT_PRIVATE
    if cgroups enabled and running on cpu >=1 (bsc#1031485)

  - The Itanium ia64 build was fixed.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1031485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7753/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7779/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7782/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7784/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7785/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7786/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7787/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7791/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7792/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7798/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7800/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7801/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7802/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7803/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7804/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7807/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172302-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6be72c16"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-MozillaFirefox-13254=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-MozillaFirefox-13254=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-MozillaFirefox-13254=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-MozillaFirefox-13254=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-MozillaFirefox-13254=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-MozillaFirefox-13254=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/31");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"MozillaFirefox-52.3.0esr-72.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"MozillaFirefox-branding-SLED-52-24.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"MozillaFirefox-translations-52.3.0esr-72.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"MozillaFirefox-52.3.0esr-72.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"MozillaFirefox-branding-SLED-52-24.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"MozillaFirefox-translations-52.3.0esr-72.9.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
