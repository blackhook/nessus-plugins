#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69268);
  script_version("1.17");
  script_cvs_date("Date: 2019/11/27");

  script_cve_id(
    "CVE-2013-1701",
    "CVE-2013-1706",
    "CVE-2013-1707",
    "CVE-2013-1709",
    "CVE-2013-1710",
    "CVE-2013-1712",
    "CVE-2013-1713",
    "CVE-2013-1714",
    "CVE-2013-1717"
  );
  script_bugtraq_id(
    61867,
    61869,
    61873,
    61874,
    61876,
    61878,
    61882,
    61896,
    61900
  );

  script_name(english:"Firefox ESR 17.x < 17.0.8 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is potentially
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox ESR 17.x is earlier than 17.0.8, and
is, therefore, potentially affected by the following vulnerabilities :

  - Various errors exist that could allow memory corruption
    conditions. (CVE-2013-1701)

  - Errors exist related to the update service and
    'maintenanceservice.exe' that could allow buffer
    overflows when handling unexpectedly long path values.
    (CVE-2013-1706, CVE-2013-1707)

  - Unspecified errors exist related to HTML frames and
    history handling, JavaScript URI handling and web
    workers using 'XMLHttpRequest' that could allow
    cross-site scripting attacks. (CVE-2013-1709,
    CVE-2013-1713, CVE-2013-1714)

  - An unspecified error exists related to generating
    'Certificate Request Message Format' (CRMF) requests
    that could allow cross-site scripting attacks.
    (CVE-2013-1710)

  - A DLL path loading error exists related to the update
    service that could allow execution of arbitrary code.
    Note this issue affects Microsoft Windows versions 7
    and greater. (CVE-2013-1712)

  - An error exists related to Java applets and 'file:///'
    URIs that could allow read-only access to arbitrary
    files. (CVE-2013-1717)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-63/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-66/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-68/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-69/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-71/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-72/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-73/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-75/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 17.0.8 ESR or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1710");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 5.0 - 15.0.1 __exposedProps__ XCS Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'17.0.8', min:'17.0', severity:SECURITY_HOLE, xss:TRUE);
