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
  script_id(42366);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-0689", "CVE-2009-3274", "CVE-2009-3370", "CVE-2009-3371", "CVE-2009-3372", "CVE-2009-3373", "CVE-2009-3374", "CVE-2009-3375", "CVE-2009-3376", "CVE-2009-3380", "CVE-2009-3381", "CVE-2009-3382", "CVE-2009-3383");

  script_name(english:"SuSE 10 Security Update : Mozilla XULRunner (ZYPP Patch Number 6616)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mozilla XULRunner engine was updated to version 1.9.0.15 to fix
various bugs and security issues.

The following security issues have been fixed :

  - Security researcher Paul Stone reported that a user's
    form history, both from web content as well as the smart
    location bar, was vulnerable to theft. A malicious web
    page could synthesize events such as mouse focus and key
    presses on behalf of the victim and trick the browser
    into auto-filling the form fields with history entries
    and then reading the entries. (MFSA 2009-52 /
    CVE-2009-3370)

  - Security researcher Jeremy Brown reported that the file
    naming scheme used for downloading a file which already
    exists in the downloads folder is predictable. If an
    attacker had local access to a victim's computer and
    knew the name of a file the victim intended to open
    through the Download Manager, he could use this
    vulnerability to place a malicious file in the
    world-writable directory used to save temporary
    downloaded files and cause the browser to choose the
    incorrect file when opening it. Since this attack
    requires local access to the victim's machine, the
    severity of this vulnerability was determined to be low.
    (MFSA 2009-53 / CVE-2009-3274)

  - Security researcher Orlando Berrera of Sec Theory
    reported that recursive creation of JavaScript
    web-workers can be used to create a set of objects whose
    memory could be freed prior to their use. These
    conditions often result in a crash which could
    potentially be used by an attacker to run arbitrary code
    on a victim's computer. (MFSA 2009-54 / CVE-2009-3371)

  - Security researcher Marco C. reported a flaw in the
    parsing of regular expressions used in Proxy
    Auto-configuration (PAC) files. In certain cases this
    flaw could be used by an attacker to crash a victim's
    browser and run arbitrary code on their computer. Since
    this vulnerability requires the victim to have PAC
    configured in their environment with specific regular
    expresssions which can trigger the crash, the severity
    of the issue was determined to be moderate. (MFSA
    2009-55 / CVE-2009-3372)

  - Security research firm iDefense reported that researcher
    regenrecht discovered a heap-based buffer overflow in
    Mozilla's GIF image parser. This vulnerability could
    potentially be used by an attacker to crash a victim's
    browser and run arbitrary code on their computer. (MFSA
    2009-56 / CVE-2009-3373)

  - Mozilla security researcher moz_bug_r_a4 reported that
    the XPCOM utility XPCVariant::VariantDataToJS unwrapped
    doubly-wrapped objects before returning them to chrome
    callers. This could result in chrome privileged code
    calling methods on an object which had previously been
    created or modified by web content, potentially
    executing malicious JavaScript code with chrome
    privileges. (MFSA 2009-57 / CVE-2009-3374)

  - Security researcher Alin Rad Pop of Secunia Research
    reported a heap-based buffer overflow in Mozilla's
    string to floating point number conversion routines.
    Using this vulnerability an attacker could craft some
    malicious JavaScript code containing a very long string
    to be converted to a floating point number which would
    result in improper memory allocation and the execution
    of an arbitrary memory location. This vulnerability
    could thus be leveraged by the attacker to run arbitrary
    code on a victim's computer. (MFSA 2009-59 /
    CVE-2009-1563)

  - Security researcher Gregory Fleischer reported that text
    within a selection on a web page can be read by
    JavaScript in a different domain using the
    document.getSelection function, violating the
    same-origin policy. Since this vulnerability requires
    user interaction to exploit, its severity was determined
    to be moderate. (MFSA 2009-61 / CVE-2009-3375)

  - Mozilla security researchers Jesse Ruderman and Sid
    Stamm reported that when downloading a file containing a
    right-to-left override character (RTL) in the filename,
    the name displayed in the dialog title bar conflicts
    with the name of the file shown in the dialog body. An
    attacker could use this vulnerability to obfuscate the
    name and file extension of a file to be downloaded and
    opened, potentially causing a user to run an executable
    file when they expected to open a non-executable file.
    (MFSA 2009-62 / CVE-2009-3376)

  - Mozilla developers and community members identified and
    fixed several stability bugs in the browser engine used
    in Firefox and other Mozilla-based products. Some of
    these crashes showed evidence of memory corruption under
    certain circumstances and we presume that with enough
    effort at least some of these could be exploited to run
    arbitrary code. (MFSA 2009-64 / CVE-2009-3380 /
    CVE-2009-3381 / CVE-2009-3382 / CVE-2009-3383)"
  );
  # http://www.mozilla.org/security/announce/2009/mfsa2009-52.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-52/"
  );
  # http://www.mozilla.org/security/announce/2009/mfsa2009-53.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-53/"
  );
  # http://www.mozilla.org/security/announce/2009/mfsa2009-54.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-54/"
  );
  # http://www.mozilla.org/security/announce/2009/mfsa2009-55.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-55/"
  );
  # http://www.mozilla.org/security/announce/2009/mfsa2009-56.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-56/"
  );
  # http://www.mozilla.org/security/announce/2009/mfsa2009-57.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-57/"
  );
  # http://www.mozilla.org/security/announce/2009/mfsa2009-59.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-59/"
  );
  # http://www.mozilla.org/security/announce/2009/mfsa2009-61.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-61/"
  );
  # http://www.mozilla.org/security/announce/2009/mfsa2009-62.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-62/"
  );
  # http://www.mozilla.org/security/announce/2009/mfsa2009-64.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-64/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1563.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3274.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3370.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3371.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3372.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3373.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3374.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3375.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3376.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3380.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3381.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3382.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3383.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6616.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 119, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-xulrunner190-1.9.0.15-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-xulrunner190-gnomevfs-1.9.0.15-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-xulrunner190-translations-1.9.0.15-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.15-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.15-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.15-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-xulrunner190-1.9.0.15-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-xulrunner190-gnomevfs-1.9.0.15-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-xulrunner190-translations-1.9.0.15-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.15-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.15-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.15-0.4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
