#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20863);
  script_version("1.18");
  script_cve_id("CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0293", "CVE-2006-0294",
                "CVE-2006-0295", "CVE-2006-0296", "CVE-2006-0297", "CVE-2006-0298",
                "CVE-2006-0299", "CVE-2006-0749", "CVE-2006-1731", "CVE-2006-1732",
                "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1736",
                "CVE-2006-1739", "CVE-2006-1740", "CVE-2006-1741", "CVE-2006-1742");
  script_bugtraq_id(16476);

  script_name(english:"SeaMonkey < 1.0 Multiple Vulnerabilities");
  script_summary(english:"Checks for SeaMonkey < 1.0");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote Windows host is using SeaMonkey, an alternative web browser
and application suite. 

The installed version of SeaMonkey contains various security issues,
some of which can be exploited to execute arbitrary code on the
affected host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-01/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-02/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-03/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-04/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-06/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-07/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-08/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-09/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-10/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-11/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-12/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-13/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-14/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-15/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-16/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-17/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-18/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-19/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SeaMonkey 1.0 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Firefox location.QueryInterface() Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(20, 79, 119, 264, 399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/05");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/02/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/07");
 script_cvs_date("Date: 2018/07/27 18:38:15");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2006-2018 Tenable Network Security, Inc.");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");

  exit(0);
}


include("misc_func.inc");


ver = read_version_in_kb("SeaMonkey/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (ver[0] == 1 && ver[1] == 0 && ver[4] =~ "^[ab]$")
) security_hole(get_kb_item("SMB/transport"));
