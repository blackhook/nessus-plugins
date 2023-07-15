#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(18689);
 script_version("1.30");

 script_cve_id("CVE-2004-0718", "CVE-2005-1937", "CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2262", 
               "CVE-2005-2263", "CVE-2005-2264", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2267", 
               "CVE-2005-2268", "CVE-2005-2269", "CVE-2005-2270", "CVE-2005-2395");
 script_bugtraq_id(14242, 14325);

 script_name(english:"Firefox < 1.0.6 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote version of Firefox contains various security issues that
may allow an attacker execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-45/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-46/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-47/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-48/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-49/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-50/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-51/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-52/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-53/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-54/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-55/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-56/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 1.0.6 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox compareTo() Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/11");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/07/19");
 script_cvs_date("Date: 2018/07/17 12:00:07");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
script_end_attributes();

 script_summary(english:"Determines the version of Firefox");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2018 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Firefox/Version");
 exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'1.0.6', severity:SECURITY_HOLE);

