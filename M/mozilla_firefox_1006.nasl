#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60042);
  script_version("1.13");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id(
    "CVE-2012-1948",
    "CVE-2012-1950",
    "CVE-2012-1951",
    "CVE-2012-1952",
    "CVE-2012-1953",
    "CVE-2012-1954",
    "CVE-2012-1955",
    "CVE-2012-1957",
    "CVE-2012-1958",
    "CVE-2012-1959",
    "CVE-2012-1961",
    "CVE-2012-1962",
    "CVE-2012-1963",
    "CVE-2012-1964",
    "CVE-2012-1965",
    "CVE-2012-1966",
    "CVE-2012-1967"
  );
  script_bugtraq_id(
    54573,
    54574,
    54575,
    54576,
    54577,
    54578,
    54579,
    54581,
    54582,
    54583,
    54584,
    54585,
    54586
  );

  script_name(english:"Firefox 10.0.x < 10.0.6 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox 10.0.x is potentially
affected by the following security issues :

  - Several memory safety issues exist, some of which could
    potentially allow arbitrary code execution.
    (CVE-2012-1948)

  - An error related to drag and drop can allow incorrect
    URLs to be displayed. (CVE-2012-1950)

  - Several memory safety issues exist related to the Gecko
    layout engine. (CVE-2012-1951, CVE-2012-1952,
    CVE-2012-1953, CVE-2012-1954)

  - An error related to JavaScript functions
    'history.forward' and 'history.back' can allow
    incorrect URLs to be displayed. (CVE-2012-1955)

  - Cross-site scripting attacks are possible due to an
    error related to the '<embed>' tag within an RSS
    '<description>' element. (CVE-2012-1957)

  - A use-after-free error exists related to the method
    'nsGlobalWindow::PageHidden'. (CVE-2012-1958)

  - An error exists that can allow 'same-compartment
    security wrappers' (SCSW) to be bypassed.
    (CVE-2012-1959)
  
  - The 'X-Frames-Options' header is ignored if it is
    duplicated. (CVE-2012-1961)

  - A memory corruption error exists related to the method
    'JSDependentString::undepend'. (CVE-2012-1962)

  - An error related to the 'Content Security Policy' (CSP)
    implementation can allow the disclosure of OAuth 2.0
    access tokens and OpenID credentials. (CVE-2012-1963)

  - An error exists related to the certificate warning page
    that can allow 'clickjacking' thereby tricking a user
    into accepting unintended certificates. (CVE-2012-1964)

  - An error exists related to the 'feed:' URL that can
    allow cross-site scripting attacks. (CVE-2012-1965)

  - Cross-site scripting attacks are possible due to an
    error related to the 'data:' URL and context menus.
    (CVE-2012-1966)

  - An error exists related to the 'javascript:' URL that
    can allow scripts to run at elevated privileges outside
    the sandbox. (CVE-2012-1967)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-42/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-43/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-44/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-45/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-46/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-47/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-48/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-49/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-51/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-52/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-53/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-54/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-55/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-56/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 10.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1967");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/19");

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

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'10.0.6', min:'10.0', severity:SECURITY_HOLE, xss:TRUE);