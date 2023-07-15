#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155019);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/02");

  script_cve_id("CVE-2021-34784");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz07282");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz09504");
  script_xref(name:"CISCO-SA", value:"cisco-sa-pi-epnm-xss-U2JK537j");
  script_xref(name:"IAVA", value:"2021-A-0549-S");

  script_name(english:"Cisco Prime Infrastructure Stored XSS (cisco-sa-pi-epnm-xss-U2JK537j)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Prime Infrastructure installed on the remote host is prior to 3.10. It is, therefore, 
affected by a stored cross-site scripting (XSS) vulnerability in its web-based management interface due to improper 
validation of user-supplied input before returning it to users. An authenticated, remote attacker can exploit this, 
by convincing a user to click a specially crafted URL, to execute arbitrary script code in a user's browser session.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-pi-epnm-xss-U2JK537j
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2922477");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz07282");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz09504");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz07282, CSCvz09504");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34784");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_infrastructure");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_infrastructure_detect.nbin");
  script_require_keys("installed_sw/Prime Infrastructure");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var port = get_http_port(default:443);
var app_info = vcf::get_app_info(app:'Prime Infrastructure', port:port, webapp:TRUE);
var constraints = [{'fixed_version':'3.10'}];

vcf::check_granularity(app_info:app_info, sig_segments:3);

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints,
  severity:SECURITY_NOTE, 
  flags:{'xss':TRUE}
);
