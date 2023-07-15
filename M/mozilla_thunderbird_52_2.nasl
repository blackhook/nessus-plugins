#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101772);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-5470",
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
    "CVE-2017-7764",
    "CVE-2017-7765",
    "CVE-2017-7771",
    "CVE-2017-7772",
    "CVE-2017-7773",
    "CVE-2017-7774",
    "CVE-2017-7775",
    "CVE-2017-7776",
    "CVE-2017-7777",
    "CVE-2017-7778"
  );
  script_bugtraq_id(99041);
  script_xref(name:"MFSA", value:"2017-17");

  script_name(english:"Mozilla Thunderbird < 52.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Thunderbird.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Thunderbird installed on the remote Windows
host is prior to 52.2 It is, therefore, affected by multiple
vulnerabilities :

  - Multiple memory corruption issues exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code by convincing a user to visit a specially crafted
    website. (CVE-2017-5470)

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

  - A flaw exists in the isLabelSafe() function in
    nsIDNService.cpp that is triggered when handling
    characters from different unicode blocks. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted IDN domain, to spoof a valid URL and
    conduct phishing attacks. (CVE-2017-7764)

  - A flaw exists that is triggered due to improper parsing
    of long filenames when handling downloaded files. An
    unauthenticated, remote attacker can exploit this to
    cause a file to be downloaded without the
    'mark-of-the-web' applied, resulting in security
    warnings for executables not being displayed.
    (CVE-2017-7765)

  - An out-of-bounds read error exists in the Graphite
    component in the readPass() function in Pass.cpp. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the disclosure of
    memory contents. (CVE-2017-7771)

  - Multiple integer overflow conditions exist in the
    Graphite component in the decompress() function in
    Decompressor.cpp due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this to cause a denial of service condition
    or the execution of arbitrary code. (CVE-2017-7772,
    CVE-2017-7773, CVE-2017-7778)

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
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-17/");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1365602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1355039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1356558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1363396");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1361326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1359547");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1357090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1366595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1356824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1368490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1360309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1364283");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1273265");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 52.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7778");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', fix:'52.2', severity:SECURITY_HOLE);
