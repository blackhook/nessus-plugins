#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64135);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-4201", "CVE-2012-4202", "CVE-2012-4203", "CVE-2012-4204", "CVE-2012-4205", "CVE-2012-4206", "CVE-2012-4207", "CVE-2012-4208", "CVE-2012-4209", "CVE-2012-4210", "CVE-2012-4212", "CVE-2012-4213", "CVE-2012-4214", "CVE-2012-4215", "CVE-2012-4216", "CVE-2012-4217", "CVE-2012-4218", "CVE-2012-5829", "CVE-2012-5830", "CVE-2012-5833", "CVE-2012-5835", "CVE-2012-5836", "CVE-2012-5837", "CVE-2012-5838", "CVE-2012-5839", "CVE-2012-5840", "CVE-2012-5841", "CVE-2012-5842", "CVE-2012-5843");

  script_name(english:"SuSE 11.2 Security Update : Mozilla Firefox (SAT Patch Number 7093)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox has been updated to the 10.0.11 ESR security release,
which fixes various bugs and security issues.

  - Security researcher miaubiz used the Address Sanitizer
    tool to discover a series critically rated of
    use-after-free, buffer overflow, and memory corruption
    issues in shipped software. These issues are potentially
    exploitable, allowing for remote code execution. We
    would also like to thank miaubiz for reporting two
    additional use-after-free and memory corruption issues
    introduced during Firefox development that have been
    fixed before general release. (MFSA 2012-106)

    In general these flaws cannot be exploited through email
    in the Thunderbird and SeaMonkey products because
    scripting is disabled, but are potentially a risk in
    browser or browser-like contexts in those products.
    References

    The following issues have been fixed in Firefox 17 and
    ESR 10.0.11 :

  - use-after-free when loading html file on osx.
    (CVE-2012-5830)

  - Mesa crashes on certain texImage2D calls involving
    level>0. (CVE-2012-5833)

  - integer overflow, invalid write w/webgl bufferdata
    (CVE-2012-5835) The following issues have been fixed in
    Firefox 17 :

  - crash in copyTexImage2D with image dimensions too large
    for given level. (CVE-2012-5838)

  - Security researcher Abhishek Arya (Inferno) of the
    Google Chrome Security Team discovered a series
    critically rated of use-after-free and buffer overflow
    issues using the Address Sanitizer tool in shipped
    software. These issues are potentially exploitable,
    allowing for remote code execution. We would also like
    to thank Abhishek for reporting five additional
    use-after-free, out of bounds read, and buffer overflow
    flaws introduced during Firefox development that have
    been fixed before general release. (MFSA 2012-105)

    In general these flaws cannot be exploited through email
    in the Thunderbird and SeaMonkey products because
    scripting is disabled, but are potentially a risk in
    browser or browser-like contexts in those products.
    References

    The following issues have been fixed in Firefox 17 and
    ESR 10.0.11 :

  - Heap-use-after-free in nsTextEditorState::PrepareEditor.
    (CVE-2012-4214)

  - Heap-use-after-free in
    nsPlaintextEditor::FireClipboardEvent. (CVE-2012-4215)

  - Heap-use-after-free in gfxFont::GetFontEntry.
    (CVE-2012-4216)

  - Heap-buffer-overflow in nsWindow::OnExposeEvent.
    (CVE-2012-5829)

  - heap-buffer-overflow in
    gfxShapedWord::CompressedGlyph::IsClusterStart

  - CVE-2012-5839

  - Heap-use-after-free in nsTextEditorState::PrepareEditor
    (CVE-2012-5840) The following issues have been fixed in
    Firefox 17 :

  - Heap-use-after-free in XPCWrappedNative::Mark.
    (CVE-2012-4212)

  - Heap-use-after-free in nsEditor::FindNextLeafNode.
    (CVE-2012-4213)

  - Heap-use-after-free in
    nsViewManager::ProcessPendingUpdates. (CVE-2012-4217)

  - Heap-use-after-free
    BuildTextRunsScanner::BreakSink::SetBreaks.
    (CVE-2012-4218)

  - Security researcher Mariusz Mlynski reported that when a
    maliciously crafted stylesheet is inspected in the Style
    Inspector, HTML and CSS can run in a chrome privileged
    context without being properly sanitized first. This can
    lead to arbitrary code execution. (MFSA 2012-104 /
    CVE-2012-4210)

  - Security researcher Mariusz Mlynski reported that the
    location property can be accessed by binary plugins
    through top.location with a frame whose name attribute's
    value is set to 'top'. This can allow for possible
    cross-site scripting (XSS) attacks through plugins.
    (MFSA 2012-103 / CVE-2012-4209)

    In general these flaws cannot be exploited through email
    in the Thunderbird and SeaMonkey products because
    scripting is disabled, but are potentially a risk in
    browser or browser-like contexts in those products.

  - Security researcher Masato Kinugawa reported that when
    script is entered into the Developer Toolbar, it runs in
    a chrome privileged context. This allows for arbitrary
    code execution or cross-site scripting (XSS) if a user
    can be convinced to paste malicious code into the
    Developer Toolbar. (MFSA 2012-102 / CVE-2012-5837)

  - Security researcher Masato Kinugawa found when
    HZ-GB-2312 charset encoding is used for text, the '~'
    character will destroy another character near the chunk
    delimiter. This can lead to a cross-site scripting (XSS)
    attack in pages encoded in HZ-GB-2312. (MFSA 2012-101 /
    CVE-2012-4207)

  - Mozilla developer Bobby Holley reported that security
    wrappers filter at the time of property access, but once
    a function is returned, the caller can use this function
    without further security checks. This affects
    cross-origin wrappers, allowing for write actions on
    objects when only read actions should be properly
    allowed. This can lead to cross-site scripting (XSS)
    attacks. (MFSA 2012-100 / CVE-2012-5841)

    In general these flaws cannot be exploited through email
    in the Thunderbird and SeaMonkey products because
    scripting is disabled, but are potentially a risk in
    browser or browser-like contexts in those products.

  - Mozilla developer Peter Van der Beken discovered that
    same-origin XrayWrappers expose chrome-only properties
    even when not in a chrome compartment. This can allow
    web content to get properties of DOM objects that are
    intended to be chrome-only. (MFSA 2012-99 /
    CVE-2012-4208)

    In general these flaws cannot be exploited through email
    in the Thunderbird and SeaMonkey products because
    scripting is disabled, but are potentially a risk in
    browser or browser-like contexts in those products.

  - Security researcher Robert Kugler reported that when a
    specifically named DLL file on a Windows computer is
    placed in the default downloads directory with the
    Firefox installer, the Firefox installer will load this
    DLL when it is launched. In circumstances where the
    installer is run by an administrator privileged account,
    this allows for the downloaded DLL file to be run with
    administrator privileges. This can lead to arbitrary
    code execution from a privileged account. (MFSA 2012-98
    / CVE-2012-4206)

  - Mozilla developer Gabor Krizsanits discovered that
    XMLHttpRequest objects created within sandboxes have the
    system principal instead of the sandbox principal. This
    can lead to cross-site request forgery (CSRF) or
    information theft via an add-on running untrusted code
    in a sandbox. (MFSA 2012-97 / CVE-2012-4205)

  - Security researcher Scott Bell of
    Security-Assessment.com used the Address Sanitizer tool
    to discover a memory corruption in str_unescape in the
    JavaScript engine. This could potentially lead to
    arbitrary code execution. (MFSA 2012-96 / CVE-2012-4204)

    In general these flaws cannot be exploited through email
    in the Thunderbird and SeaMonkey products because
    scripting is disabled, but are potentially a risk in
    browser or browser-like contexts in those products.

  - Security researcher kakzz.ng@gmail.com reported that if
    a javascript: URL is selected from the list of Firefox
    'new tab' page, the script will inherit the privileges
    of the privileged 'new tab' page. This allows for the
    execution of locally installed programs if a user can be
    convinced to save a bookmark of a malicious javascript:
    URL. (MFSA 2012-95 / CVE-2012-4203)

  - Security researcher Jonathan Stephens discovered that
    combining SVG text on a path with the setting of CSS
    properties could lead to a potentially exploitable
    crash. (MFSA 2012-94 / CVE-2012-5836)

  - Mozilla security researcher moz_bug_r_a4 reported that
    if code executed by the evalInSandbox function sets
    location.href, it can get the wrong subject principal
    for the URL check, ignoring the sandbox's JavaScript
    context and gaining the context of evalInSandbox object.
    This can lead to malicious web content being able to
    perform a cross-site scripting (XSS) attack or stealing
    a copy of a local file if the user has installed an
    add-on vulnerable to this attack. (MFSA 2012-93 /
    CVE-2012-4201)

  - Security researcher Atte Kettunen from OUSPG used the
    Address Sanitizer tool to discover a buffer overflow
    while rendering GIF format images. This issue is
    potentially exploitable and could lead to arbitrary code
    execution. (MFSA 2012-92 / CVE-2012-4202)

  - Mozilla developers identified and fixed several memory
    safety bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these bugs showed
    evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2012-91)

    In general these flaws cannot be exploited through email
    in the Thunderbird and SeaMonkey products because
    scripting is disabled, but are potentially a risk in
    browser or browser-like contexts in those products.
    References

    Gary Kwong, Jesse Ruderman, Christian Holler, Bob Clary,
    Kyle Huey, Ed Morley, Chris Lord, Boris Zbarsky, Julian
    Seward, and Bill McCloskey reported memory safety
    problems and crashes that affect Firefox 16.
    (CVE-2012-5843)

    Jesse Ruderman, Andrew McCreight, Bob Clary, and Kyle
    Huey reported memory safety problems and crashes that
    affect Firefox ESR 10 and Firefox 16. (CVE-2012-5842)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-100.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-101.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-102.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-103.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-104.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-105.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-106.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-91.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-92.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-93.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-94.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-95.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-96.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-97.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-98.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-99.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=790140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4201.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4202.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4203.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4204.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4205.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4206.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4207.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4208.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4209.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4210.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4212.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4213.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4214.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4215.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4216.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4217.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4218.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5829.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5830.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5833.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5836.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5837.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5838.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5839.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5840.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5841.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5842.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5843.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7093.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"MozillaFirefox-10.0.11-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"MozillaFirefox-translations-10.0.11-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libfreebl3-3.14-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mozilla-nss-3.14-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mozilla-nss-tools-3.14-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"MozillaFirefox-10.0.11-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"MozillaFirefox-translations-10.0.11-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libfreebl3-3.14-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libfreebl3-32bit-3.14-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nss-3.14-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nss-32bit-3.14-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nss-tools-3.14-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"MozillaFirefox-10.0.11-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"MozillaFirefox-translations-10.0.11-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"libfreebl3-3.14-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mozilla-nss-3.14-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mozilla-nss-tools-3.14-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"libfreebl3-32bit-3.14-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"mozilla-nss-32bit-3.14-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libfreebl3-32bit-3.14-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"mozilla-nss-32bit-3.14-0.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
