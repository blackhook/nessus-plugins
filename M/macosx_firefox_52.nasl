#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97637);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id(
    "CVE-2017-5398",
    "CVE-2017-5399",
    "CVE-2017-5400",
    "CVE-2017-5401",
    "CVE-2017-5402",
    "CVE-2017-5403",
    "CVE-2017-5404",
    "CVE-2017-5405",
    "CVE-2017-5406",
    "CVE-2017-5407",
    "CVE-2017-5408",
    "CVE-2017-5410",
    "CVE-2017-5412",
    "CVE-2017-5413",
    "CVE-2017-5414",
    "CVE-2017-5415",
    "CVE-2017-5416",
    "CVE-2017-5417",
    "CVE-2017-5418",
    "CVE-2017-5419",
    "CVE-2017-5420",
    "CVE-2017-5421",
    "CVE-2017-5422",
    "CVE-2017-5425",
    "CVE-2017-5427"
  );
  script_bugtraq_id(
    96651,
    96654,
    96664,
    96677,
    96691,
    96692,
    96693
  );
  script_xref(name:"MFSA", value:"2017-05");

  script_name(english:"Mozilla Firefox < 52.0 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS or Mac OS X host contains a web browser that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote macOS or Mac
OS X host is prior to 52.0. It is, therefore, affected by
multiple vulnerabilities :

  - Mozilla developers and community members Boris Zbarsky,
    Christian Holler, Honza Bambas, Jon Coppeard, Randell
    Jesup, Andre Bargull, Kan-Ru Chen, and Nathan Froyd
    reported memory safety bugs present in Firefox 51 and
    Firefox ESR 45.7. Some of these bugs showed evidence of
    memory corruption and we presume that with enough
    effort that some of these could be exploited to run
    arbitrary code. (CVE-2017-5398)

  - Mozilla developers and community members Carsten Book,
    Calixte Denizet, Christian Holler, Andrew McCreight,
    David Bolter, David Keeler, Jon Coppeard, Tyson Smith,
    Ronald Crane, Tooru Fujisawa, Ben Kelly, Bob Owen, Jed
    Davis, Julian Seward, Julian Hector, Philipp, Markus
    Stange, and Andre Bargull reported memory safety bugs
    present in Firefox 51. Some of these bugs showed
    evidence of memory corruption and we presume that with
    enough effort that some of these could be exploited to
    run arbitrary code. (CVE-2017-5399)

  - JIT-spray targeting asm.js combined with a heap spray
    allows for a bypass of ASLR and DEP protections leading
    to potential memory corruption attacks. (CVE-2017-5400)

  - A crash triggerable by web content in which an
    ErrorResult references unassigned memory due to a logic
    error. The resulting crash may be exploitable.
    (CVE-2017-5401)

  - A use-after-free can occur when events are fired for a
    FontFace object after the object has been already been
    destroyed while working with fonts. This results in a
    potentially exploitable crash. (CVE-2017-5402)

  - When adding a range to an object in the DOM, it is
    possible to use addRange to add the range to an
    incorrect root object. This triggers a use-after-free,
    resulting in a potentially exploitable crash.
    (CVE-2017-5403)

  - A use-after-free error can occur when manipulating
    ranges in selections with one node inside a native
    anonymous tree and one node outside of it. This results
    in a potentially exploitable crash. (CVE-2017-5404)

  - Certain response codes in FTP connections can result in
    the use of uninitialized values for ports in FTP
    operations. (CVE-2017-5405)

  - A segmentation fault can occur in the Skia graphics
    library during some canvas operations due to issues
    with mask/clip intersection and empty masks.
    (CVE-2017-5406)

  - Using SVG filters that don't use the fixed point math
    implementation on a target iframe, a malicious page can
    extract pixel values from a targeted user. This can be
    used to extract history information and read text
    values across domains. This violates same-origin policy
    and leads to information disclosure. (CVE-2017-5407)

  - Video files loaded video captions cross-origin without
    checking for the presence of CORS headers permitting
    such cross-origin use, leading to potential information
    disclosure for video captions. (CVE-2017-5408)

  - Memory corruption resulting in a potentially
    exploitable crash during garbage collection of
    JavaScript due errors in how incremental sweeping is
    managed for memory cleanup. (CVE-2017-5410)

  - A buffer overflow read during SVG filter color value
    operations, resulting in data exposure. (CVE-2017-5412)

  - A segmentation fault can occur during some
    bidirectional layout operations. (CVE-2017-5413)

  - The file picker dialog can choose and display the wrong
    local default directory when instantiated. On some
    operating systems, this can lead to information
    disclosure, such as the operating system or the local
    account name. (CVE-2017-5414)

  - An attack can use a blob URL and script to spoof an
    arbitrary addressbar URL prefaced by blob: as the
    protocol, leading to user confusion and further
    spoofing attacks. (CVE-2017-5415)

  - In certain circumstances a networking event listener
    can be prematurely released. This appears to result in
    a null dereference in practice. (CVE-2017-5416)

  - When dragging content from the primary browser pane to
    the addressbar on a malicious site, it is possible to
    change the addressbar so that the displayed location
    following navigation does not match the URL of the
    newly loaded page. This allows for spoofing attacks.
    (CVE-2017-5417)

  - An out of bounds read error occurs when parsing some
    HTTP digest authorization responses, resulting in
    information leakage through the reading of random
    memory containing matches to specifically set patterns.
    (CVE-2017-5418)

  - If a malicious site repeatedly triggers a modal
    authentication prompt, eventually the browser UI will
    become non-responsive, requiring shutdown through the
    operating system. This is a denial of service (DOS)
    attack. (CVE-2017-5419)

  - A javascript: url loaded by a malicious page can
    obfuscate its location by blanking the URL displayed in
    the addressbar, allowing for an attacker to spoof an
    existing page without the malicious page's address
    being displayed correctly. (CVE-2017-5420)

  - A malicious site could spoof the contents of the print
    preview window if popup windows are enabled, resulting
    in user confusion of what site is currently loaded.
    (CVE-2017-5421)

  - If a malicious site uses the view-source: protocol in a
    series within a single hyperlink, it can trigger a
    non-exploitable browser crash when the hyperlink is
    selected. This was fixed by no longer making
    view-source: linkable. (CVE-2017-5422)

  - The Gecko Media Plugin sandbox allows access to local
    files that match specific regular expressions. On OS
    OX, this matching allows access to some data in
    subdirectories of /private/var that could expose
    personal or temporary data. This has been updated to
    not allow access to /private/var and its
    subdirectories. Note: this issue only affects OS X.
    Other operating systems are not affected.
    (CVE-2017-5425)

  - A non-existent chrome.manifest file will attempt to be
    loaded during startup from the primary installation
    directory. If a malicious user with local access puts
    chrome.manifest and other referenced files in this
    directory, they will be loaded and activated during
    startup. This could result in malicious software being
    added without consent or modification of referenced
    installed files. (CVE-2017-5427)

Note that Tenable Network Security has extracted the preceding
description block directly from the Mozilla security advisories.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-05/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 52.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5399");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

is_esr = get_kb_item(kb_base+"/is_esr");
if (!isnull(is_esr)) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'firefox', fix:'52.0', severity:SECURITY_HOLE);
