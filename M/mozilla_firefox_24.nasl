#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69993);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/27");

  script_cve_id(
    "CVE-2013-1718",
    "CVE-2013-1719",
    "CVE-2013-1720",
    "CVE-2013-1721",
    "CVE-2013-1722",
    "CVE-2013-1723",
    "CVE-2013-1724",
    "CVE-2013-1725",
    "CVE-2013-1726",
    "CVE-2013-1728",
    "CVE-2013-1730",
    "CVE-2013-1732",
    "CVE-2013-1735",
    "CVE-2013-1736",
    "CVE-2013-1737",
    "CVE-2013-1738"
  );
  script_bugtraq_id(
    62460,
    62462,
    62463,
    62464,
    62465,
    62466,
    62467,
    62468,
    62469,
    62470,
    62472,
    62473,
    62475,
    62478,
    62479,
    62482
  );

  script_name(english:"Firefox < 24.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is potentially
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox is earlier than 24.0 and is,
therefore, potentially affected by the following vulnerabilities :

  - Memory issues exist in the browser engine that could
    allow for denial of service or arbitrary code execution.
    (CVE-2013-1718, CVE-2013-1719)

  - The HTML5 Tree Builder does not properly maintain
    states, which could result in a denial of service or
    possible arbitrary code execution.  (CVE-2013-1720)

  - The ANGLE library is vulnerable to an integer overflow,
    which could result in a denial of service or arbitrary
    code execution. (CVE-2013-1721)

  - Multiple use-after-free problems exist that could result
    in denial of service attacks or arbitrary code
    execution. (CVE-2013-1722, CVE-2013-1724, CVE-2013-1735,
    CVE-2013-1736, CVE-2013-1738)

  - The NativeKey widget does not properly terminate key
    messages, possibly leading to a denial of service attack.
    (CVE-2013-1723)

  - Incorrect scope handling for JavaScript objects with
    compartments could result in denial of service or
    possibly arbitrary code execution. (CVE-2013-1725)

  - Local users can gain the same privileges as the Mozilla
    Updater because the application does not ensure
    exclusive access to the update file. An attacker could
    exploit this by inserting a malicious file into the
    update file. (CVE-2013-1726)

  - Sensitive information can be obtained via unspecified
    vectors because the IonMonkey JavaScript does not
    properly initialize memory. (CVE-2013-1728)

  - A JavaScript compartment mismatch can result in a denial
    of service or arbitrary code execution.  Versions of
    Firefox 20 or greater are not susceptible to the
    arbitrary code execution mentioned above.
    (CVE-2013-1730)

  - A buffer overflow is possible because of an issue with
    multi-column layouts. (CVE-2013-1732)

  - An object is not properly identified during use of
    user-defined getter methods on DOM proxies.  This could
    result in access restrictions being bypassed.
    (CVE-2013-1737)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-76/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-77/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-78/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-79/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-80/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-81/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-82/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-83/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-85/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-88/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-89/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-90/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-91/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-92/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 24.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1736");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/19");

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

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'24.0', severity:SECURITY_HOLE, xss:FALSE);
