#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(130503);
  script_version("1.2");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2019-1821", "CVE-2019-1822", "CVE-2019-1823");
  script_bugtraq_id(108339);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo22842");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo28671");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo28680");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo62258");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo62264");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo62280");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-pi-rce");

  script_name(english:"Cisco Prime Infrastructure Multiple Vulnerabilities (cisco-sa-20190515-pi-rce)");
  script_summary(english:"Checks the Cisco Prime Infrastructure version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The Cisco Prime Infrastructure application running on the remote
host is affected by the following vulnerabilities :

  - An unspecified flaw exists that allows a remote,
    unauthenticated attacker to execute arbitrary code.
    (CVE-2019-1821)

  - An unspecified flaw exists that allows a remote,
    authenticated attacker to execute arbitrary code.
    (CVE-2019-1822, CVE-2019-1823)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-pi-rce
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce4c9325");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo22842");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo28671");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo28680");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo62258");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo62264");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo62280");
  script_set_attribute(attribute:"solution", value:
"Upgrade Cisco Prime Infrastructure to version 3.4.1 Update 01, 3.5.0
Update 03, or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1821");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cisco Prime Infrastructure Health Monitor TarArchive Directory Traversal Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_infrastructure");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_infrastructure_detect.nbin");
  script_require_keys("installed_sw/Prime Infrastructure");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

port = get_http_port(default:443);
app_info = vcf::get_app_info(app:'Prime Infrastructure', port:port, webapp:TRUE);

constraints = [
  {'min_version':'3.4', 'fixed_version':'3.4.1.1', 'fixed_display':'3.4.1 Update 01 / 3.6'},
  {'min_version':'3.5', 'fixed_version':'3.5.0.3', 'fixed_display':'3.5.0 Update 03 / 3.6'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
