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
  script_id(52652);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2010-1585", "CVE-2010-3777", "CVE-2011-0051", "CVE-2011-0053", "CVE-2011-0054", "CVE-2011-0055", "CVE-2011-0056", "CVE-2011-0057", "CVE-2011-0058", "CVE-2011-0059", "CVE-2011-0062");

  script_name(english:"SuSE 10 Security Update : mozilla-xulrunner191 (ZYPP Patch Number 7363)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla XULRunner 1.9.1 has been updated to version 1.9.1.17, fixing
the following security issues :

  - Several memory safety bugs in the browser engine used in
    Firefox and other Mozilla-based products have been
    identified and fixed. Some of these bugs showed evidence
    of memory corruption under certain circumstances, and it
    is assumed that with enough effort at least some of
    these could be exploited to run arbitrary code. (MFSA
    2010-74 / CVE-2010-3777)

  - Several memory safety bugs in the browser engine used in
    Firefox and other Mozilla-based products have been
    identified and fixed. Some of these bugs showed evidence
    of memory corruption under certain circumstances, and it
    is assumed that with enough effort at least some of
    these could be exploited to run arbitrary code. (MFSA
    2011-01 / CVE-2011-0053 / CVE-2011-0062)

  - A recursive call to eval() wrapped in a try/catch
    statement places the browser into a inconsistent state.
    Any dialog box opened in this state is displayed without
    text and with non-functioning buttons. Closing the
    window causes the dialog to evaluate to true. An
    attacker could use this issue to force a user into
    accepting any dialog, such as one granting elevated
    privileges to the page presenting the dialog. (MFSA
    2011-02 / CVE-2011-0051)

  - A method used by JSON.stringify contains a
    use-after-free error in which a currently in-use pointer
    was freed and subsequently dereferenced. This could lead
    to arbitrary code execution if an attacker is able to
    store malicious code in the freed section of memory.
    (MFSA 2011-03 / CVE-2011-0055)

  - The JavaScript engine's internal memory mapping of
    non-local JS variables contains a buffer overflow which
    could potentially be used by an attacker to run
    arbitrary code on a victim's computer. (MFSA 2011-04 /
    CVE-2011-0054)

  - The JavaScript engine's internal mapping of string
    values contains an error in cases where the number of
    values being stored is above 64K. In such cases an
    offset pointer is manually moved forwards and backwards
    to access the larger address space. If an exception is
    thrown between the time that the offset pointer was
    moved forward and the time it gets reset, the exception
    object would be read from an invalid memory address,
    potentially executing attacker-controlled memory. (MFSA
    2011-05 / CVE-2011-0056)

  - A JavaScript Worker could be used to keep a reference to
    an object that could be freed during garbage collection.
    Subsequent calls through this deleted reference could
    cause attacker-controlled memory to be executed on a
    victim's computer. (MFSA 2011-06 / CVE-2011-0057)

  - When very long strings are constructed and inserted into
    an HTML document, the browser incorrectly constructs the
    layout objects used to display the text. Under such
    conditions an incorrect length would be calculated for a
    text run resulting in too small of a memory buffer being
    allocated to store the text. This issue could be used by
    an attacker to write data past the end of the buffer and
    execute malicious code on a victim's computer. It
    affects only Mozilla browsers on Windows. (MFSA 2011-07
    / CVE-2011-0058)

  - ParanoidFragmentSink, a class used to sanitize
    potentially unsafe HTML for display, allows javascript:
    URLs and other inline JavaScript when the embedding
    document is a chrome document. While there are no unsafe
    uses of this class in any released products, extension
    code could potentially use it in an unsafe manner. (MFSA
    2011-08 / CVE-2010-1585)

  - When plugin-initiated requests receive a 307 redirect
    response, the plugin is not notified and the request is
    forwarded to the new location. This is true even for
    cross-site redirects, so any custom headers that were
    added as part of the initial request would be forwarded
    intact across origins. This poses a CSRF risk for web
    applications that rely on custom headers only being
    present in requests from their own origin. (MFSA 2011-10
    / CVE-2011-0059)"
  );
  # http://www.mozilla.org/security/announce/2010/mfsa2010-74.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-74/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-01.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-01/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-02.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-02/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-03.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-03/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-05.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-05/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-06.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-06/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-07.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-07/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-08.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-08/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-10.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-10/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1585.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3777.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0051.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0053.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0054.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0055.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0056.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0057.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0058.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0059.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0062.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7363.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/14");
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
if (rpm_check(release:"SLED10", sp:3, reference:"mozilla-xulrunner191-1.9.1.17-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"mozilla-xulrunner191-gnomevfs-1.9.1.17-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"mozilla-xulrunner191-translations-1.9.1.17-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.17-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-32bit-1.9.1.17-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner191-translations-32bit-1.9.1.17-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-xulrunner191-1.9.1.17-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-xulrunner191-gnomevfs-1.9.1.17-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-xulrunner191-translations-1.9.1.17-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.17-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-32bit-1.9.1.17-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner191-translations-32bit-1.9.1.17-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
