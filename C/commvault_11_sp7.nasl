#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125782);
  script_version("1.4");
  script_cvs_date("Date: 2019/07/25  7:07:22");

  script_cve_id("CVE-2017-3195","CVE-2017-18044");
  script_bugtraq_id(96941);
  script_xref(name:"IAVA", value:"2019-A-0181");

  script_name(english:"Commvault 11 < 11 SP7 Multiple Vulnerabilities");
  script_summary(english:"Checks for the product version and service pack.");

  script_set_attribute(attribute:"synopsis", value:
"The Commvault install running on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Commvault running on the remote web server is 11 prior
to 11 SP7. It is, therefore, affected by multiple vulnerabilities:

  - A buffer overflow vulnerability exists in the Commvault Edge 
    communication service (cvd). An remote, unauthenticated 
    attacker could achieve arbitrary code execution by sending 
    a specially crafted packet. (CVE-2017-3195)

  - A command injection vulnerability exists in CVDataPipe.dll. 
    An unauthenticated, remote attacker can exploit this, via 
    a specially crafted message to CreateProcess, to execute 
    arbitrary commands as SYSTEM. (CVE-2017-18044)");
  # https://www.securifera.com/advisories/cve-2017-18044/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f582085c");
  # http://kb.commvault.com/article/SEC0013
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7d23884");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Commvault v11 SP6 and install hotfix 590, v11 SP7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3195");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Commvault Communications Service (cvd) Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:commvault:commvault");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("commvault_web_console_detect.nbin");
  script_require_keys("installed_sw/Commvault", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("http.inc");
include("vcf.inc");
include("vcf_extras.inc");

# Can't detect hotfix
if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

# get_app_info wrapper converts version string to <version>-SP<service pack>
# for ease of writing constraints
app = vcf::commvault::get_webapp_info(port:port);

constraints = [{"min_version" : "11", "fixed_version" : "11-SP7", "fixed_display":"11 SP6 & hotfix 590 / 11 SP7"}];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE);
