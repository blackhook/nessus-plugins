#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71347);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/27");

  script_cve_id(
    "CVE-2013-5609",
    "CVE-2013-5610",
    "CVE-2013-5611",
    "CVE-2013-5612",
    "CVE-2013-5613",
    "CVE-2013-5614",
    "CVE-2013-5615",
    "CVE-2013-5616",
    "CVE-2013-5618",
    "CVE-2013-5619",
    "CVE-2013-6629",
    "CVE-2013-6630",
    "CVE-2013-6671",
    "CVE-2013-6673"
  );
  script_bugtraq_id(
    63676,
    63679,
    64203,
    64204,
    64205,
    64206,
    64207,
    64209,
    64211,
    64212,
    64213,
    64214,
    64215,
    64216
  );

  script_name(english:"Firefox < 26.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is potentially
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox is earlier than 26.0 and is,
therefore, potentially affected by the following vulnerabilities :

  - Memory issues exist in the browser engine that could
    result in a denial of service or arbitrary code
    execution. (CVE-2013-5609, CVE-2013-5610)

  - An issue exists where the notification for a Web App
    installation could persist from one website to another
    website. This could be used by a malicious website to
    trick a user into installing an application from one
    website while making it appear to come from another
    website. (CVE-2013-5611)

  - Cross-site scripting filtering evasion may be possible
    due to character encodings being inherited from a
    previously visited website when character set encoding
    is missing from the current website. (CVE-2013-5612)

  - Two use-after-free vulnerabilities exist in the
    functions for synthetic mouse movement handling.
    (CVE-2013-5613)

  - Sandbox restrictions may be bypassed because 'iframe
    sandbox' restrictions are not properly applied to
    'object' elements in sandboxed iframes. (CVE-2013-5614)

  - An issue exists in which 'GetElementIC' typed array
    stubs can be generated outside observed typesets. This
    could lead to unpredictable behavior with a potential
    security impact. (CVE-2013-5615)

  - A use-after-free vulnerability exists when
    interacting with event listeners from the mListeners
    array.  This could result in a denial of service or
    arbitrary code execution. (CVE-2013-5616)

  - A use-after-free vulnerability exists in the table
    editing user interface of the editor during garbage
    collection.  This could result in a denial of service or
    arbitrary code execution. (CVE-2013-5618)

  - Memory issues exist in the binary search algorithms in
    the SpiderMonkey JavaScript engine that could result in
    a denial of service or arbitrary code execution.
    (CVE-2013-5619)

  - Issues exist with the JPEG format image processing with
    Start Of Scan (SOS) and Define Huffman Table (DHT)
    markers in the 'libjpeg' library.  This could allow
    attackers to read arbitrary memory content as well as
    cross-domain image theft. (CVE-2013-6629, CVE-2013-6630)

  - A memory issue exists when inserting an ordered list
    into a document through a script that could result in a
    denial of service or arbitrary code execution.
    (CVE-2013-6671)

  - Trust settings for built-in root certificates are
    ignored during extended validation (EV) certificate
    validation.  This removes the ability of users to
    explicitly untrust root certificates from specific
    certificate authorities. (CVE-2013-6673)

  - An intermediate certificate that is used by a man-in-
    the-middle (MITM) traffic management device exists in
    Mozilla's root certificate authorities.  Reportedly,
    this certificate has been misused.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-104/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-105/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-106/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-107/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-108/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-109/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-110/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-111/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-113/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-114/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-115/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-116/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-117/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 26.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-5618");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'26.0', severity:SECURITY_HOLE, xss:TRUE);
