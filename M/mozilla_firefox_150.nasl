#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61715);
  script_version("1.20");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id(
    "CVE-2012-1956",
    "CVE-2012-1970",
    "CVE-2012-1971",
    "CVE-2012-1972",
    "CVE-2012-1973",
    "CVE-2012-1974",
    "CVE-2012-1975",
    "CVE-2012-1976",
    "CVE-2012-3956",
    "CVE-2012-3957",
    "CVE-2012-3958",
    "CVE-2012-3959",
    "CVE-2012-3960",
    "CVE-2012-3961",
    "CVE-2012-3962",
    "CVE-2012-3963",
    "CVE-2012-3964",
    "CVE-2012-3965",
    "CVE-2012-3966",
    "CVE-2012-3968",
    "CVE-2012-3969",
    "CVE-2012-3970",
    "CVE-2012-3971",
    "CVE-2012-3972",
    "CVE-2012-3973",
    "CVE-2012-3974",
    "CVE-2012-3975",
    "CVE-2012-3976",
    "CVE-2012-3978",
    "CVE-2012-3980",
    "CVE-2012-4930"
  );
  script_bugtraq_id(
    55249,
    55256,
    55257,
    55260,
    55264,
    55266,
    55274,
    55276,
    55278,
    55292,
    55304,
    55306,
    55308,
    55310,
    55311,
    55312,
    55313,
    55314,
    55316,
    55317,
    55318,
    55319,
    55320,
    55321,
    55322,
    55323,
    55324,
    55325,
    55340,
    55341,
    55342
  );

  script_name(english:"Firefox < 15.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox is earlier than 15.0 and thus, is
potentially affected by the following security issues :

  - An error exists related to 'Object.defineProperty'
    and the location object and  can allow cross-site
    scripting attacks. (CVE-2012-1956)

  - Unspecified memory safety issues exist. (CVE-2012-1970,
    CVE-2012-1971)

  - Multiple use-after-free errors exist. (CVE-2012-1972,
    CVE-2012-1973, CVE-2012-1974, CVE-2012-1975,
    CVE-2012-1976, CVE-2012-3956, CVE-2012-3957,
    CVE-2012-3958, CVE-2012-3959, CVE-2012-3960,
    CVE-2012-3961, CVE-2012-3962, CVE-2012-3963,
    CVE-2012-3964)

  - An error exists related to 'about:newtab' and the
    browser's history. This error can allow a newly opened
    tab to further open a new window and navigate to the
    privileged 'about:newtab' page leading to possible
    privilege escalation. (CVE-2012-3965)

  - An error exists related to bitmap (BMP) and icon (ICO)
    file decoding that can lead to memory corruption
    causing application crashes and potentially arbitrary
    code execution. (CVE-2012-3966)

  - A use-after-free error exists related to WebGL shaders.
    (CVE-2012-3968)

  - A buffer overflow exists related to SVG filters.
    (CVE-2012-3969)

  - A use-after-free error exists related to elements
    having 'requiredFeatures' attributes. (CVE-2012-3970)

  - A 'Graphite 2' library memory corruption error exists.
    (CVE-2012-3971)

  - An XSLT out-of-bounds read error exists related to
    'format-number'. (CVE-2012-3972)

  - Remote debugging is possible even when disabled and the
    'HTTPMonitor' extension is enabled. (CVE-2012-3973)

  - The installer can be ticked into running unauthorized
    executables. (CVE-2012-3974)

  - The DOM parser can unintentionally load linked
    resources in extensions. (CVE-2012-3975)

  - Incorrect SSL certificate information can be displayed
    in the address bar when two 'onLocationChange' events
    fire out of order. (CVE-2012-3976)

  - Security checks related to location objects can be
    bypassed if crafted calls are made to the browser
    chrome code. (CVE-2012-3978)

  - Calling 'eval' in the web console can allow injected
    code to be executed with browser chrome privileges.
    (CVE-2012-3980)

  - SPDY's request header compression leads to information
    leakage, which can allow private data such as session
    cookies to be extracted, even over an SSL connection.
    (CVE-2012-4930)");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524145/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-57/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-58/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-59/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-60/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-61/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-62/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-63/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-64/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-65/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-66/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-67/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-68/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-69/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-70/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-72/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-73/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 15.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-3971");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'15.0', severity:SECURITY_HOLE, xss:TRUE);
