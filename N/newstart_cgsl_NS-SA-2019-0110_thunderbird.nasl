#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0110. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127347);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2016-10195",
    "CVE-2016-10196",
    "CVE-2016-10197",
    "CVE-2017-5398",
    "CVE-2017-5400",
    "CVE-2017-5401",
    "CVE-2017-5402",
    "CVE-2017-5404",
    "CVE-2017-5405",
    "CVE-2017-5407",
    "CVE-2017-5408",
    "CVE-2017-5410",
    "CVE-2017-5429",
    "CVE-2017-5432",
    "CVE-2017-5433",
    "CVE-2017-5434",
    "CVE-2017-5435",
    "CVE-2017-5436",
    "CVE-2017-5438",
    "CVE-2017-5439",
    "CVE-2017-5440",
    "CVE-2017-5441",
    "CVE-2017-5442",
    "CVE-2017-5443",
    "CVE-2017-5444",
    "CVE-2017-5445",
    "CVE-2017-5446",
    "CVE-2017-5447",
    "CVE-2017-5449",
    "CVE-2017-5451",
    "CVE-2017-5454",
    "CVE-2017-5459",
    "CVE-2017-5460",
    "CVE-2017-5464",
    "CVE-2017-5465",
    "CVE-2017-5466",
    "CVE-2017-5467",
    "CVE-2017-5469",
    "CVE-2017-5470",
    "CVE-2017-5472",
    "CVE-2017-7749",
    "CVE-2017-7750",
    "CVE-2017-7751",
    "CVE-2017-7752",
    "CVE-2017-7754",
    "CVE-2017-7756",
    "CVE-2017-7757",
    "CVE-2017-7758",
    "CVE-2017-7764",
    "CVE-2017-7771",
    "CVE-2017-7772",
    "CVE-2017-7773",
    "CVE-2017-7774",
    "CVE-2017-7775",
    "CVE-2017-7776",
    "CVE-2017-7777",
    "CVE-2017-7778"
  );

  script_name(english:"NewStart CGSL MAIN 4.05 : thunderbird Multiple Vulnerabilities (NS-SA-2019-0110)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has thunderbird packages installed that are affected by
multiple vulnerabilities:

  - A buffer overflow in WebGL triggerable by web content,
    resulting in a potentially exploitable crash. This
    vulnerability affects Thunderbird < 52.1, Firefox ESR <
    45.9, Firefox ESR < 52.1, and Firefox < 53.
    (CVE-2017-5459)

  - An out-of-bounds read during the processing of glyph
    widths during text layout. This results in a potentially
    exploitable crash and could allow an attacker to read
    otherwise inaccessible memory. This vulnerability
    affects Thunderbird < 52.1, Firefox ESR < 45.9, Firefox
    ESR < 52.1, and Firefox < 53. (CVE-2017-5447)

  - An out-of-bounds read when an HTTP/2 connection to a
    servers sends DATA frames with incorrect data content.
    This leads to a potentially exploitable crash. This
    vulnerability affects Thunderbird < 52.1, Firefox ESR <
    45.9, Firefox ESR < 52.1, and Firefox < 53.
    (CVE-2017-5446)

  - A possibly exploitable crash triggered during layout and
    manipulation of bidirectional unicode text in concert
    with CSS animations. This vulnerability affects
    Thunderbird < 52.1, Firefox ESR < 52.1, and Firefox <
    53. (CVE-2017-5449)

  - A use-after-free vulnerability during changes in style
    when manipulating DOM elements. This results in a
    potentially exploitable crash. This vulnerability
    affects Thunderbird < 52.1, Firefox ESR < 45.9, Firefox
    ESR < 52.1, and Firefox < 53. (CVE-2017-5442)

  - An out-of-bounds write vulnerability while decoding
    improperly formed BinHex format archives. This
    vulnerability affects Thunderbird < 52.1, Firefox ESR <
    45.9, Firefox ESR < 52.1, and Firefox < 53.
    (CVE-2017-5443)

  - A buffer overflow vulnerability while parsing
    application/http-index-format format content when the
    header contains improperly formatted data. This allows
    for an out-of-bounds read of data from memory. This
    vulnerability affects Thunderbird < 52.1, Firefox ESR <
    45.9, Firefox ESR < 52.1, and Firefox < 53.
    (CVE-2017-5444)

  - A use-after-free vulnerability when holding a selection
    during scroll events. This results in a potentially
    exploitable crash. This vulnerability affects
    Thunderbird < 52.1, Firefox ESR < 45.9, Firefox ESR <
    52.1, and Firefox < 53. (CVE-2017-5441)

  - A potential memory corruption and crash when using Skia
    content when drawing content outside of the bounds of a
    clipping region. This vulnerability affects Thunderbird
    < 52.1, Firefox ESR < 52.1, and Firefox < 53.
    (CVE-2017-5467)

  - A mechanism to bypass file system access protections in
    the sandbox to use the file picker to access different
    files than those selected in the file picker through the
    use of relative paths. This allows for read only access
    to the local file system. This vulnerability affects
    Thunderbird < 52.1, Firefox ESR < 52.1, and Firefox <
    53. (CVE-2017-5454)

  - A mechanism to spoof the addressbar through the user
    interaction on the addressbar and the onblur event.
    The event could be used by script to affect text display
    to make the loaded site appear to be different from the
    one actually loaded within the addressbar. This
    vulnerability affects Thunderbird < 52.1, Firefox ESR <
    52.1, and Firefox < 53. (CVE-2017-5451)

  - A use-after-free vulnerability occurs during certain
    text input selection resulting in a potentially
    exploitable crash. This vulnerability affects
    Thunderbird < 52.1, Firefox ESR < 45.9, Firefox ESR <
    52.1, and Firefox < 53. (CVE-2017-5432)

  - A use-after-free vulnerability in frame selection
    triggered by a combination of malicious script content
    and key presses by a user. This results in a potentially
    exploitable crash. This vulnerability affects
    Thunderbird < 52.1, Firefox ESR < 45.9, Firefox ESR <
    52.1, and Firefox < 53. (CVE-2017-5460)

  - During DOM manipulations of the accessibility tree
    through script, the DOM tree can become out of sync with
    the accessibility tree, leading to memory corruption and
    a potentially exploitable crash. This vulnerability
    affects Thunderbird < 52.1, Firefox ESR < 45.9, Firefox
    ESR < 52.1, and Firefox < 53. (CVE-2017-5464)

  - Fixed potential buffer overflows in generated Firefox
    code due to CVE-2016-6354 issue in Flex. This
    vulnerability affects Thunderbird < 52.1, Firefox ESR <
    45.9, Firefox ESR < 52.1, and Firefox < 53.
    (CVE-2017-5469)

  - An out-of-bounds read while processing SVG content in
    ConvolvePixel. This results in a crash and also allows
    for otherwise inaccessible memory being copied into SVG
    graphic content, which could then displayed. This
    vulnerability affects Thunderbird < 52.1, Firefox ESR <
    45.9, Firefox ESR < 52.1, and Firefox < 53.
    (CVE-2017-5465)

  - If a page is loaded from an original site through a
    hyperlink and contains a redirect to a data:text/html
    URL, triggering a reload will run the reloaded
    data:text/html page with its origin set incorrectly.
    This allows for a cross-site scripting (XSS) attack.
    This vulnerability affects Thunderbird < 52.1, Firefox
    ESR < 52.1, and Firefox < 53. (CVE-2017-5466)

  - A use-after-free vulnerability in SMIL animation
    functions occurs when pointers to animation elements in
    an array are dropped from the animation controller while
    still in use. This results in a potentially exploitable
    crash. This vulnerability affects Thunderbird < 52.1,
    Firefox ESR < 45.9, Firefox ESR < 52.1, and Firefox <
    53. (CVE-2017-5433)

  - A use-after-free vulnerability occurs when redirecting
    focus handling which results in a potentially
    exploitable crash. This vulnerability affects
    Thunderbird < 52.1, Firefox ESR < 45.9, Firefox ESR <
    52.1, and Firefox < 53. (CVE-2017-5434)

  - A use-after-free vulnerability during XSLT processing
    due to the result handler being held by a freed handler
    during handling. This results in a potentially
    exploitable crash. This vulnerability affects
    Thunderbird < 52.1, Firefox ESR < 45.9, Firefox ESR <
    52.1, and Firefox < 53. (CVE-2017-5438)

  - A use-after-free vulnerability during XSLT processing
    due to poor handling of template parameters. This
    results in a potentially exploitable crash. This
    vulnerability affects Thunderbird < 52.1, Firefox ESR <
    45.9, Firefox ESR < 52.1, and Firefox < 53.
    (CVE-2017-5439)

  - A use-after-free vulnerability occurs during transaction
    processing in the editor during design mode
    interactions. This results in a potentially exploitable
    crash. This vulnerability affects Thunderbird < 52.1,
    Firefox ESR < 45.9, Firefox ESR < 52.1, and Firefox <
    53. (CVE-2017-5435)

  - Memory safety bugs were reported in Thunderbird 45.7.
    Some of these bugs showed evidence of memory corruption
    and we presume that with enough effort that some of
    these could be exploited to run arbitrary code. This
    vulnerability affects Firefox < 52, Firefox ESR < 45.8,
    Thunderbird < 52, and Thunderbird < 45.8.
    (CVE-2017-5398)

  - JIT-spray targeting asm.js combined with a heap spray
    allows for a bypass of ASLR and DEP protections leading
    to potential memory corruption attacks. This
    vulnerability affects Firefox < 52, Firefox ESR < 45.8,
    Thunderbird < 52, and Thunderbird < 45.8.
    (CVE-2017-5400)

  - A crash triggerable by web content in which an
    ErrorResult references unassigned memory due to a
    logic error. The resulting crash may be exploitable.
    This vulnerability affects Firefox < 52, Firefox ESR <
    45.8, Thunderbird < 52, and Thunderbird < 45.8.
    (CVE-2017-5401)

  - A use-after-free can occur when events are fired for a
    FontFace object after the object has been already been
    destroyed while working with fonts. This results in a
    potentially exploitable crash. This vulnerability
    affects Firefox < 52, Firefox ESR < 45.8, Thunderbird <
    52, and Thunderbird < 45.8. (CVE-2017-5402)

  - A use-after-free error can occur when manipulating
    ranges in selections with one node inside a native
    anonymous tree and one node outside of it. This results
    in a potentially exploitable crash. This vulnerability
    affects Firefox < 52, Firefox ESR < 45.8, Thunderbird <
    52, and Thunderbird < 45.8. (CVE-2017-5404)

  - Certain response codes in FTP connections can result in
    the use of uninitialized values for ports in FTP
    operations. This vulnerability affects Firefox < 52,
    Firefox ESR < 45.8, Thunderbird < 52, and Thunderbird <
    45.8. (CVE-2017-5405)

  - Using SVG filters that don't use the fixed point math
    implementation on a target iframe, a malicious page can
    extract pixel values from a targeted user. This can be
    used to extract history information and read text values
    across domains. This violates same-origin policy and
    leads to information disclosure. This vulnerability
    affects Firefox < 52, Firefox ESR < 45.8, Thunderbird <
    52, and Thunderbird < 45.8. (CVE-2017-5407)

  - Video files loaded video captions cross-origin without
    checking for the presence of CORS headers permitting
    such cross-origin use, leading to potential information
    disclosure for video captions. This vulnerability
    affects Firefox < 52, Firefox ESR < 45.8, Thunderbird <
    52, and Thunderbird < 45.8. (CVE-2017-5408)

  - Memory corruption resulting in a potentially exploitable
    crash during garbage collection of JavaScript due errors
    in how incremental sweeping is managed for memory
    cleanup. This vulnerability affects Firefox < 52,
    Firefox ESR < 45.8, Thunderbird < 52, and Thunderbird <
    45.8. (CVE-2017-5410)

  - An out-of-bounds read vulnerability with the Opus
    encoder when the number of channels in an audio stream
    changes while the encoder is in use. This vulnerability
    affects Firefox < 54, Firefox ESR < 52.2, and
    Thunderbird < 52.2. (CVE-2017-7758)

  - A use-after-free vulnerability in IndexedDB when one of
    its objects is destroyed in memory while a method on it
    is still being executed. This results in a potentially
    exploitable crash. This vulnerability affects Firefox <
    54, Firefox ESR < 52.2, and Thunderbird < 52.2.
    (CVE-2017-7757)

  - A number of security vulnerabilities in the Graphite 2
    library including out-of-bounds reads, buffer overflow
    reads and writes, and the use of uninitialized memory.
    These issues were addressed in Graphite 2 version
    1.3.10. This vulnerability affects Firefox < 54, Firefox
    ESR < 52.2, and Thunderbird < 52.2. (CVE-2017-7778)

  - An out of bounds read vulnerability was found in
    libevent in the search_make_new function. If an attacker
    could cause an application using libevent to attempt
    resolving an empty hostname, an out of bounds read could
    occur possibly leading to a crash. (CVE-2016-10197)

  - A vulnerability was found in libevent with the parsing
    of DNS requests and replies. An attacker could send a
    forged DNS response to an application using libevent
    which could lead to reading data out of bounds on the
    heap, potentially disclosing a small amount of
    application memory. (CVE-2016-10195)

  - A vulnerability was found in libevent with the parsing
    of IPv6 addresses. If an attacker could cause an
    application using libevent to parse a malformed address
    in IPv6 notation of more than 2GiB in length, a stack
    overflow would occur leading to a crash.
    (CVE-2016-10196)

  - An assertion error has been reported in graphite2. An
    attacker could possibly exploit this flaw to cause an
    application crash. (CVE-2017-7775)

  - A use-after-free vulnerability during video control
    operations when a  element holds a reference to
    an older window if that window has been replaced in the
    DOM. This results in a potentially exploitable crash.
    This vulnerability affects Firefox < 54, Firefox ESR <
    52.2, and Thunderbird < 52.2. (CVE-2017-7750)

  - A use-after-free and use-after-scope vulnerability when
    logging errors from headers for XML HTTP Requests (XHR).
    This could result in a potentially exploitable crash.
    This vulnerability affects Firefox < 54, Firefox ESR <
    52.2, and Thunderbird < 52.2. (CVE-2017-7756)

  - A use-after-free vulnerability when using an incorrect
    URL during the reloading of a docshell. This results in
    a potentially exploitable crash. This vulnerability
    affects Firefox < 54, Firefox ESR < 52.2, and
    Thunderbird < 52.2. (CVE-2017-7749)

  - A use-after-free vulnerability during specific user
    interactions with the input method editor (IME) in some
    languages due to how events are handled. This results in
    a potentially exploitable crash but would require
    specific user interaction to trigger. This vulnerability
    affects Firefox < 54, Firefox ESR < 52.2, and
    Thunderbird < 52.2. (CVE-2017-7752)

  - A use-after-free vulnerability with content viewer
    listeners that results in a potentially exploitable
    crash. This vulnerability affects Firefox < 54, Firefox
    ESR < 52.2, and Thunderbird < 52.2. (CVE-2017-7751)

  - A use-after-free vulnerability with the frameloader
    during tree reconstruction while regenerating CSS layout
    when attempting to use a node in the tree that no longer
    exists. This results in a potentially exploitable crash.
    This vulnerability affects Firefox < 54, Firefox ESR <
    52.2, and Thunderbird < 52.2. (CVE-2017-5472)

  - An out-of-bounds read in WebGL with a maliciously
    crafted ImageInfo object during WebGL operations. This
    vulnerability affects Firefox < 54, Firefox ESR < 52.2,
    and Thunderbird < 52.2. (CVE-2017-7754)

  - Memory safety bugs were reported in Firefox 53 and
    Firefox ESR 52.1. Some of these bugs showed evidence of
    memory corruption and we presume that with enough effort
    that some of these could be exploited to run arbitrary
    code. This vulnerability affects Firefox < 54, Firefox
    ESR < 52.2, and Thunderbird < 52.2. (CVE-2017-5470)

  - An out of bounds read flaw related to
    graphite2::Silf::readGraphite has been reported in
    graphite2. An attacker could possibly exploit this flaw
    to disclose potentially sensitive memory or cause an
    application crash. (CVE-2017-7774)

  - A heap-based buffer overflow flaw related to
    lz4::decompress (src/Decompressor) has been reported
    in graphite2. An attacker could exploit this issue to
    cause a crash or, possibly, execute arbitrary code.
    (CVE-2017-7773)

  - A heap-based buffer overflow flaw related to
    lz4::decompress has been reported in graphite2. An
    attacker could exploit this issue to cause a crash or,
    possibly, execute arbitrary code. (CVE-2017-7772)

  - An out of bounds read flaw related to
    graphite2::Pass::readPass has been reported in
    graphite2. An attacker could possibly exploit this flaw
    to disclose potentially sensitive memory or cause an
    application crash. (CVE-2017-7771)

  - The use of uninitialized memory related to
    graphite2::GlyphCache::Loader::read_glyph has been
    reported in graphite2. An attacker could possibly
    exploit this flaw to negatively impact the execution of
    an application using graphite2 in unknown ways.
    (CVE-2017-7777)

  - An out of bounds read flaw related to
    graphite2::Silf::getClassGlyph has been reported in
    graphite2. An attacker could possibly exploit this flaw
    to disclose potentially sensitive memory or cause an
    application crash. (CVE-2017-7776)

  - Characters from the Canadian Syllabics unicode block
    can be mixed with characters from other unicode blocks
    in the addressbar instead of being rendered as their raw
    punycode form, allowing for domain name spoofing
    attacks through character confusion. The current Unicode
    standard allows characters from Aspirational Use
    Scripts such as Canadian Syllabics to be mixed with
    Latin characters in the moderately restrictive IDN
    profile. We have changed Firefox behavior to match the
    upcoming Unicode version 10.0 which removes this
    category and treats them as Limited Use Scripts.. This
    vulnerability affects Firefox < 54, Firefox ESR < 52.2,
    and Thunderbird < 52.2. (CVE-2017-7764)

  - Memory safety bugs were reported in Firefox 52, Firefox
    ESR 45.8, Firefox ESR 52, and Thunderbird 52. Some of
    these bugs showed evidence of memory corruption and we
    presume that with enough effort that some of these could
    be exploited to run arbitrary code. This vulnerability
    affects Thunderbird < 52.1, Firefox ESR < 45.9, Firefox
    ESR < 52.1, and Firefox < 53. (CVE-2017-5429)

  - A vulnerability while parsing application/http-index-
    format format content where uninitialized values are
    used to create an array. This could allow the reading of
    uninitialized memory into the arrays affected. This
    vulnerability affects Thunderbird < 52.1, Firefox ESR <
    45.9, Firefox ESR < 52.1, and Firefox < 53.
    (CVE-2017-5445)

  - A use-after-free vulnerability during XSLT processing
    due to a failure to propagate error conditions during
    matching while evaluating context, leading to objects
    being used when they no longer exist. This results in a
    potentially exploitable crash. This vulnerability
    affects Thunderbird < 52.1, Firefox ESR < 45.9, Firefox
    ESR < 52.1, and Firefox < 53. (CVE-2017-5440)

  - An out-of-bounds write in the Graphite 2 library
    triggered with a maliciously crafted Graphite font. This
    results in a potentially exploitable crash. This issue
    was fixed in the Graphite 2 library as well as Mozilla
    products. This vulnerability affects Thunderbird < 52.1,
    Firefox ESR < 45.9, Firefox ESR < 52.1, and Firefox <
    53. (CVE-2017-5436)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0110");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL thunderbird packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5398");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "thunderbird-52.2.0-1.el6.centos"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
