#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140220);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/08");

  script_cve_id("CVE-2019-1906");
  script_bugtraq_id(108855);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo46881");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq37787");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190619-prime-privescal");

  script_name(english:"Cisco Prime Infrastructure Virtual Domain Privilege Escalation (cisco-sa-20190619-prime-privescal)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Prime Infrastructure application running on the remote host is
2.2(2.0.78) prior to 3.1(2.0.0) or 3.5(0.0) prior to 3.5(1). It is, therefore, affected by a privilege escalation
vulnerability in the Virtual Domain system due to improper validation of API requests. An authenticated, remote
attacker can exploit this by sending a crafted request to the server in order to change the virtual domain
configuration and possibly elevate privileges.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190619-prime-privescal
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?357030b9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo46881");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq37787");
  script_set_attribute(attribute:"solution", value:
"Upgrade Cisco Prime Infrastructure to version 3.1.(2.0.0), 3.5(1), or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1906");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_infrastructure");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '2.2.2.0.78', 'fixed_version' : '3.1.2', 'fixed_display' : '3.1(2.0.0)' },
  { 'min_version' : '3.5', 'fixed_version' : '3.5.1', 'fixed_display' : '3.5(1)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

