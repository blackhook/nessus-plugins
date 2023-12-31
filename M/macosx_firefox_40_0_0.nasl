#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85384);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id(
    "CVE-2015-4473",
    "CVE-2015-4474",
    "CVE-2015-4475",
    "CVE-2015-4477",
    "CVE-2015-4478",
    "CVE-2015-4479",
    "CVE-2015-4480",
    "CVE-2015-4482",
    "CVE-2015-4483",
    "CVE-2015-4484",
    "CVE-2015-4485",
    "CVE-2015-4486",
    "CVE-2015-4487",
    "CVE-2015-4488",
    "CVE-2015-4489",
    "CVE-2015-4490",
    "CVE-2015-4492",
    "CVE-2015-4493"
  );
  script_bugtraq_id(76294, 76297);

  script_name(english:"Firefox < 40 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Mac OS X host is prior
to 40. It is, therefore, affected by the following vulnerabilities :

  - Multiple memory corruption issues exist that allow a
    remote attacker, via a specially crafted web page, to
    corrupt memory and potentially execute arbitrary code.
    (CVE-2015-4473)

  - Multiple memory corruption issues exist that allow a
    remote attacker, via a specially crafted web page, to
    corrupt memory and potentially execute arbitrary code.
    (CVE-2015-4474)

  - An out-of-bounds read error exists in the
    PlayFromAudioQueue() function due to improper handling
    of mismatched sample formats. A remote attacker can
    exploit this, via a specially crafted MP3 file, to
    disclose memory contents or execute arbitrary code.
    (CVE-2015-4475)

  - A use-after-free error exists in the Web Audio API
    during MediaStream playback. A remote attacker can
    exploit this to dereference already freed memory,
    resulting in the potential execution of arbitrary code.
    (CVE-2015-4477)

  - A same-origin policy bypass vulnerability exists due to
    non-configurable properties being redefined in violation
    of the ECMAScript 6 standard during JSON parsing. A
    remote attacker can exploit this, by editing these
    properties to arbitrary values, to bypass the
    same-origin policy. (CVE-2015-4478)

  - Multiple integer overflow conditions exist due to
    improper validation of user-supplied input when handling
    'saio' chunks in MPEG4 video. A remote attacker can
    exploit this, via a specially crafted MPEG4 file, to
    execute arbitrary code. (CVE-2015-4479)

  - An integer overflow condition exists in the bundled
    libstagefright component when handling H.264 media
    content. A remote attacker can exploit this, via a
    specially crafted MPEG4 file, to execute arbitrary code.
    (CVE-2015-4480)

  - An out-of-bounds write error exists due to an array
    indexing flaw in the mar_consume_index() function when
    handling index names in MAR files. An attacker can
    exploit this to execute arbitrary code. (CVE-2015-4482)

  - A security bypass vulnerability exists due to a flaw in
    the ShouldLoad() function that occurs during the
    handling of POST requests to URLs using the 'feed:' URI
    handler. An attacker can exploit this to bypass the
    mixed content blocker. (CVE-2015-4483)

  - A denial of service vulnerability exists when handling
    JavaScript using shared memory without properly gating
    access to Atomics and SharedArrayBuffer views. An
    attacker can exploit this to crash the program,
    resulting in a denial of service condition.
    (CVE-2015-4484)

  - A heap-based buffer overflow condition exists in the 
    resize_context_buffers() function due to improper
    validation of user-supplied input. A remote attacker can
    exploit this, via specially crafted WebM content, to
    cause a heap-based buffer overflow, resulting in the
    execution of arbitrary code. (CVE-2015-4485)

  - A heap-based buffer overflow condition exists in the 
    decrease_ref_count() function due to improper validation
    of user-supplied input. A remote attacker can exploit
    this, via specially crafted WebM content, to cause a
    heap-based buffer overflow, resulting in the execution
    of arbitrary code. (CVE-2015-4486)

  - A buffer overflow condition exists in the ReplacePrep()
    function. A remote attacker can exploit this to cause a
    buffer overflow, resulting in the execution of arbitrary
    code. (CVE-2015-4487)

  - A use-after-free error exists in the operator=()
    function. An attacker can exploit this to dereference
    already freed memory, resulting in the execution of
    arbitrary code. (CVE-2015-4488)

  - A memory corruption issue exists in the nsTArray_Impl()
    function due to improper validation of user-supplied
    input during self-assignment. An attacker can exploit
    this to corrupt memory, resulting in the execution of
    arbitrary code. (CVE-2015-4489)

  - A security bypass vulnerability exists due to a
    discrepancy in the implementation of Content Security
    Policy and the CSP specification. The specification
    states that 'blob:', 'data:', and 'filesystem:' URLs
    should be excluded in case of a wildcard when matching
    source expressions, but Mozilla's implementation allows
    these in the case of an asterisk wildcard. A remote
    attacker can exploit this to bypass restrictions.
    (CVE-2015-4490)

  - A use-after-free error exists in the
    XMLHttpRequest::Open() function due to improper handling
    of recursive calls. An attacker can exploit this to
    dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2015-4492)

  - An integer underflow condition exists in the bundled
    libstagefright library. An attacker can exploit this to
    crash the application, resulting in a denial of service
    condition. (CVE-2015-4493)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-79/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-80/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-81/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-82/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-83/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-85/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-86/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-87/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-89/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-90/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-91/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-92/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 40 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4486");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'40', severity:SECURITY_HOLE);
