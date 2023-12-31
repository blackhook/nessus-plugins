#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72328);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/26");

  script_cve_id(
    "CVE-2014-1477",
    "CVE-2014-1478",
    "CVE-2014-1479",
    "CVE-2014-1480",
    "CVE-2014-1481",
    "CVE-2014-1482",
    "CVE-2014-1483",
    "CVE-2014-1485",
    "CVE-2014-1486",
    "CVE-2014-1487",
    "CVE-2014-1488",
    "CVE-2014-1489",
    "CVE-2014-1490",
    "CVE-2014-1491"
  );
  script_bugtraq_id(
    65316,
    65317,
    65320,
    65321,
    65322,
    65324,
    65326,
    65328,
    65329,
    65330,
    65331,
    65332,
    65334,
    65335
  );

  script_name(english:"Firefox < 27.0 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is potentially
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox is earlier than 27.0 and is,
therefore, potentially affected by multiple vulnerabilities :

  - Memory issues exist in the browser engine that could
    result in a denial of service or arbitrary code
    execution. (CVE-2014-1477, CVE-2014-1478)

  - An error exists related to System Only Wrappers (SOW)
    and the XML Binding Language (XBL) that could allow
    XUL content to be disclosed. (CVE-2014-1479)

  - An error exists related to the 'open file' dialog that
    could allow users to take unintended actions.
    (CVE-2014-1480)

  - An error exists related to the JavaScript engine and
    'window' object handling that has unspecified impact.
    (CVE-2014-1481)

  - An error exists related to 'RasterImage' and image
    decoding that could allow application crashes and
    possibly arbitrary code execution. (CVE-2014-1482)

  - Errors exist related to IFrames,
    'document.caretPositionFromPoint' and
    'document.elementFromPoint' that could allow cross-
    origin information disclosure. (CVE-2014-1483)

  - An error exists related to the Content Security
    Policy (CSP) and XSLT stylesheets that could allow
    unintended script execution.  (CVE-2014-1485)

  - A use-after-free error exists related to image handling
    and 'imgRequestProxy' that could allow application
    crashes and possibly arbitrary code execution.
    (CVE-2014-1486)

  - An error exists related to 'web workers' that could
    allow cross-origin information disclosure.
    (CVE-2014-1487)

  - An error exists related to 'web workers' and 'asm.js'
    that could allow application crashes and possibly
    arbitrary code execution. (CVE-2014-1488)

  - An error exists that could allow webpages to access
    activate content from the 'about:home' page that
    could lead to data loss. (CVE-2014-1489)

  - Network Security Services (NSS) contains a race
    condition in libssl that occurs during session ticket 
    processing. A remote attacker can exploit this flaw
    to cause a denial of service. (CVE-2014-1490)

  - Network Security Services (NSS) does not properly
    restrict public values in Diffie-Hellman key exchanges,
    allowing a remote attacker to bypass cryptographic
    protection mechanisms. (CVE-2014-1491)");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-058/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-01/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-02/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-03/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-04/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-05/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-07/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-08/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-09/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-10/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-11/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-12/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-13/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 27.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1488");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'27.0', severity:SECURITY_HOLE, xss:FALSE);
