#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123796);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/05");

  script_cve_id("CVE-2019-10656", "CVE-2019-10657", "CVE-2019-10658");

  script_name(english:"Blind Command Injection Vulnerability in Grandstream Products");
  script_summary(english:"The Grandstream device uses firmware which contains a blind command injection vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is vulnerable and can be compromised");
  script_set_attribute(attribute:"description", value:
"A Blind Command Injection Vulnerability exists in Grandstream 
devices:

   - The affected devices are: GWN7000 & GWN7610

   - A blind command injection vulnerability exists in the 'filename'
     parameter. An unauthenticated, remote attacker can exploit this 
     to bypass authentication and obtain a root shell.");
  script_set_attribute(attribute:"solution", value:
"Update to the fixed version as per the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10656");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  # https://www.trustwave.com/en-us/resources/security-resources/security-advisories/?fid=23920
  script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?0e9e1acb");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/08");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("grandstream_networking_solutions_web_detect.nbin");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

port = get_http_port(default:80, embedded:TRUE);
app_info = vcf::get_app_info(app:'Grandstream Networking Solutions', port:port);

models = {
  'GWN7000' : { 'constraints': [{'max_version' : '1.0.4.12', 'fixed_version' : '1.0.6.32', 'fixed_display' : '1.0.6.32'}]},
  'GWN7610' : { 'constraints': [{'max_version' : '1.0.8.9',  'fixed_version' : '1.0.8.18', 'fixed_display' : '1.0.8.18'}]}
};

vcf::grandstream::check_version_and_report(app_info:app_info, constraints:models[app_info.Model]['constraints'], severity:SECURITY_HOLE);
