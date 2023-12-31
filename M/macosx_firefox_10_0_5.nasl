#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59404);
  script_version("1.11");
  script_cvs_date("Date: 2018/07/14  1:59:35");

  script_cve_id(
    "CVE-2012-0441",
    "CVE-2012-1937",
    "CVE-2012-1939",
    "CVE-2012-1940",
    "CVE-2012-1941",
    "CVE-2012-1944",
    "CVE-2012-1946",
    "CVE-2012-1947"
  );
  script_bugtraq_id(
    53791,
    53792,
    53793,
    53794,
    53797,
    53798,
    53800,
    53801
  );

  script_name(english:"Firefox < 10.0.5 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Firefox is earlier than 10.0.5 and thus, is
potentially affected by the following security issues :

  - An error exists in the ASN.1 decoder when handling zero
    length items that can lead to application crashes.
    (CVE-2012-0441)

  - Multiple memory corruption errors exist. (CVE-2012-1937,
    CVE-2012-1939)

  - Two heap-based buffer overflows and one heap-based use-
    after-free error exist and are potentially exploitable.
    (CVE-2012-1940, CVE-2012-1941, CVE-2012-1947)

  - The inline-script blocking feature of the 'Content
    Security Policy' (CSP) does not properly block inline
    event handlers. This error allows remote attackers to
    more easily carry out cross-site scripting attacks.
    (CVE-2012-1944)

  - A use-after-free error exists related to replacing or
    inserting a node into a web document. (CVE-2012-1946)"
  );
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-34/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-36/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-38/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-39/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-40/");
 
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 10.0.5 ESR or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'10.0.5', severity:SECURITY_HOLE);