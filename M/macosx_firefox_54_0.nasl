#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100808);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id(
    "CVE-2017-5470",
    "CVE-2017-5471",
    "CVE-2017-5472",
    "CVE-2017-7749",
    "CVE-2017-7750",
    "CVE-2017-7751",
    "CVE-2017-7752",
    "CVE-2017-7754",
    "CVE-2017-7755",
    "CVE-2017-7756",
    "CVE-2017-7757",
    "CVE-2017-7758",
    "CVE-2017-7760",
    "CVE-2017-7761",
    "CVE-2017-7762",
    "CVE-2017-7763",
    "CVE-2017-7764",
    "CVE-2017-7772",
    "CVE-2017-7774",
    "CVE-2017-7775",
    "CVE-2017-7776",
    "CVE-2017-7777",
    "CVE-2017-7778"
  );
  script_bugtraq_id(
    99040,
    99041,
    99042,
    99047,
    99057
  );
  script_xref(name:"MFSA", value:"2017-15");

  script_name(english:"Mozilla Firefox < 54 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote macOS or Mac
OS X host is prior to 54. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple memory corruption issues exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code by convincing a user to visit a specially crafted
    website. (CVE-2017-5470, CVE-2017-5471)

  - A use-after-free error exists in the EndUpdate()
    function in nsCSSFrameConstructor.cpp that is triggered
    when reconstructing trees during regeneration of CSS
    layouts. An unauthenticated, remote attacker can exploit
    this, by convincing a user to visit a specially crafted
    website, to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2017-5472)

  - A use-after-free error exists in the Reload() function
    in nsDocShell.cpp that is triggered when using an
    incorrect URL during the reload of a docshell. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2017-7749)

  - A use-after-free error exists in the Hide() function in
    nsDocumentViewer.cpp that is triggered when handling
    track elements. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition or
    the execution of arbitrary code. (CVE-2017-7750)

  - A use-after-free error exists in the nsDocumentViewer
    class in nsDocumentViewer.cpp that is triggered when
    handling content viewer listeners. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2017-7751)

  - A use-after-free error exists that is triggered when
    handling events while specific user interaction occurs
    with the input method editor (IME). An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2017-7752)

  - An out-of-bounds read error exists in the IsComplete()
    function in WebGLTexture.cpp that is triggered when
    handling textures. An unauthenticated, remote attacker
    can exploit this to disclose memory contents.
    (CVE-2017-7754)

  - A privilege escalation vulnerability exists due to
    improper loading of dynamic-link library (DLL) files. A
    local attacker can exploit this, via a specially crafted
    DLL file in the installation path, to inject and execute
    arbitrary code. (CVE-2017-7755)

  - A use-after-free error exists in the SetRequestHead()
    function in XMLHttpRequestMainThread.cpp that is
    triggered when logging XML HTTP Requests (XHR). An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2017-7756)

  - A use-after-free error exists in ActorsParent.cpp due to
    improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2017-7757)

  - An out-of-bounds read error exists in the
    AppendAudioSegment() function in TrackEncoder.cpp that
    is triggered when the number of channels in an audio
    stream changes while the Opus encoder is in use. An
    unauthenticated, remote attacker can exploit this to
    disclose sensitive information. (CVE-2017-7758)

  - A flaw exists in the NS_main() function in updater.cpp
    due to improper validation of input when handling
    callback file path parameters. A local attacker can
    exploit this to manipulate files in the installation
    directory. (CVE-2017-7760)

  - A flaw exists in the Maintenance Service helper.exe
    application that is triggered as permissions for a
    temporary directory are set to writable by
    non-privileged users. A local attacker can exploit this
    to delete arbitrary files on the system. (CVE-2017-7761)

  - A flaw exists that is triggered when displaying URLs
    including authentication sections in reader mode. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted URL, to spoof domains in the address
    bar. (CVE-2017-7762)

  - A flaw exists in the ReadCMAP() function in
    gfxMacPlatformFontList.mm that is triggered when
    handling tibetan characters in combination with macOS
    fonts. An unauthenticated, remote attacker can exploit
    this, via a specially crafted IDN domain, to spoof a
    valid URL. (CVE-2017-7763)

  - A flaw exists in the isLabelSafe() function in
    nsIDNService.cpp that is triggered when handling
    characters from different unicode blocks. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted IDN domain, to spoof a valid URL and
    conduct phishing attacks. (CVE-2017-7764)

  - Multiple integer overflow conditions exist in the
    Graphite component in the decompress() function in
    Decompressor.cpp due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this to cause a denial of service condition
    or the execution of arbitrary code. (CVE-2017-7772,
    CVE-2017-7778)

  - An out-of-bounds read error exists in the Graphite
    component in the readGraphite() function in Silf.cpp. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or disclose memory
    contents. (CVE-2017-7774)

  - An assertion flaw exists in the Graphite component when
    handling zero value sizes. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (CVE-2017-7775)

  - An out-of-bounds read error exists in the Graphite
    component in getClassGlyph() function in Silf.cpp due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2017-7776)

  - A flaw exists in the Graphite component in the
    read_glyph() function in GlyphCache.cpp related to use
    of uninitialized memory. An unauthenticated, remote
    attacker can exploit this to have an unspecified impact.
    (CVE-2017-7777)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-15/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 54 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7778");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (get_kb_item(kb_base + '/is_esr')) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'54', severity:SECURITY_HOLE);
