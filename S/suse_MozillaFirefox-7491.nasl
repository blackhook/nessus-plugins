#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(53649);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2011-0065", "CVE-2011-0066", "CVE-2011-0067", "CVE-2011-0069", "CVE-2011-0070", "CVE-2011-0071", "CVE-2011-0072", "CVE-2011-0073", "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0076", "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0080", "CVE-2011-0081", "CVE-2011-1202");

  script_name(english:"SuSE 10 Security Update : Mozilla Firefox (ZYPP Patch Number 7491)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to the 3.6.17 security release.

  - Mozilla developers identified and fixed several memory
    safety bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these bugs showed
    evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. Credits. (MFSA 2011-12)

    Mozilla developer Scoobidiver reported a memory safety
    issue which affected Firefox 4 and Firefox 3.6.
    (CVE-2011-0081)

    The web development team of Alcidion reported a crash
    that affected Firefox 4, Firefox 3.6 and Firefox 3.5.
    (CVE-2011-0069)

    Ian Beer reported a crash that affected Firefox 4,
    Firefox 3.6 and Firefox 3.5. (CVE-2011-0070)

    Mozilla developers Bob Clary, Henri Sivonen, Marco
    Bonardo, Mats Palmgren and Jesse Ruderman reported
    memory safety issues which affected Firefox 3.6 and
    Firefox 3.5. (CVE-2011-0080)

    Aki Helin reported memory safety issues which affected
    Firefox 3.6 and Firefox 3.5. (CVE-2011-0074 /
    CVE-2011-0075)

    Ian Beer reported memory safety issues which affected
    Firefox 3.6 and Firefox 3.5. (CVE-2011-0077 /
    CVE-2011-0078)

    Martin Barbella reported a memory safety issue which
    affected Firefox 3.6 and Firefox 3.5. (CVE-2011-0072)

  - Security researcher regenrecht reported several dangling
    pointer vulnerabilities via TippingPoint's Zero Day
    Initiative. (MFSA 2011-13 / CVE-2011-0065 /
    CVE-2011-0066 / CVE-2011-0073)

  - Security researcher Paul Stone reported that a Java
    applet could be used to mimic interaction with form
    autocomplete controls and steal entries from the form
    history. (MFSA 2011-14 / CVE-2011-0067)

  - David Remahl of Apple Product Security reported that the
    Java Embedding Plugin (JEP) shipped with the Mac OS X
    versions of Firefox could be exploited to obtain
    elevated access to resources on a user's system. (MFSA
    2011-15 / CVE-2011-0076)

  - Security researcher Soroush Dalili reported that the
    resource: protocol could be exploited to allow directory
    traversal on Windows and the potential loading of
    resources from non-permitted locations. The impact would
    depend on whether interesting files existed in
    predictable locations in a useful format. For example,
    the existence or non-existence of particular images
    might indicate whether certain software was installed.
    (MFSA 2011-16 / CVE-2011-0071)

  - Chris Evans of the Chrome Security Team reported that
    the XSLT generate-id() function returned a string that
    revealed a specific valid address of an object on the
    memory heap. It is possible that in some cases this
    address would be valuable information that could be used
    by an attacker while exploiting a different memory
    corruption but, in order to make an exploit more
    reliable or work around mitigation features in the
    browser or operating system. (MFSA 2011-18 /
    CVE-2011-1202)"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-12.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-12/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-13.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-13/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-14.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-14/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-15.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-15/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-16.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-16/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-18.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-18/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0065.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0066.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0067.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0069.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0070.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0071.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0072.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0073.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0074.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0075.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0076.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0078.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0080.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0081.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1202.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7491.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox "nsTreeRange" Dangling Pointer Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLES10", sp:3, reference:"MozillaFirefox-3.6.17-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"MozillaFirefox-translations-3.6.17-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-xulrunner192-1.9.2.17-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-xulrunner192-gnome-1.9.2.17-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-xulrunner192-translations-1.9.2.17-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.17-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.17-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner192-translations-32bit-1.9.2.17-0.6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
