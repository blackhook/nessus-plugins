##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142908);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-27130");
  script_xref(name:"CISCO-SA", value:"cisco-sa-csm-path-trav-NgeRnqgR");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu99995");
  script_xref(name:"IAVA", value:"2020-A-0535");
  script_xref(name:"CEA-ID", value:"CEA-2020-0136");

  script_name(english:"Cisco Security Manager < 4.22 Path Traversal (cisco-sa-csm-path-trav-NgeRnqgR)");

  script_set_attribute(attribute:"synopsis", value:
"The web application running on the remote web server is affected by a path traversal vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Security Manager running on the remote web server is prior to 4.22. It is, therefore, affected 
a path traversal vulnerability. An unauthenticated, remote attacker can exploit this, by sending a URI that 
contains directory traversal characters, to disclose the contents of files located outside of the server's restricted 
path.

Please see the included Cisco BID and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-csm-path-trav-NgeRnqgR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c337be85");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu99995");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Security Manager version 4.22 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27130");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:security_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_security_manager_http_detect.nbin");
  script_require_keys("installed_sw/Cisco Security Manager");

  exit(0);
}

include('http.inc');
include('vcf.inc');

port = get_http_port(default:443);
app_info = vcf::get_app_info(app:'Cisco Security Manager', port:port);
constraints = [{'fixed_version':'4.22'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
