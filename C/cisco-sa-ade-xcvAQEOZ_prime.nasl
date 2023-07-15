#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150026);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/10");

  script_cve_id("CVE-2021-1306");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv57166");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ade-xcvAQEOZ");
  script_xref(name:"IAVA", value:"2021-A-0248");

  script_name(english:"Cisco ADE-OS Local File Inclusion (cisco-sa-ade-xcvAQEOZ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Prime Infrastructure Software is affected by a local file inclusion
vulnerability. A vulnerability in the restricted shell of Cisco Prime Infrastructure Software could allow an
authenticated, local attacker to identify directories and write arbitrary files to the file system. This vulnerability
is due to improper validation of parameters that are sent to a CLI command within the restricted shell. An attacker
could exploit this vulnerability by logging in to the device and issuing certain CLI commands. A successful exploit
could allow the attacker to identify file directories on the affected device and write arbitrary files to the file
system on the affected device. To exploit this vulnerability, the attacker must be an authenticated shell user.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ade-xcvAQEOZ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?937d9a01");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv57166");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv57166.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1306");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_infrastructure");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_infrastructure_detect.nbin");
  script_require_keys("installed_sw/Prime Infrastructure");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var port = get_http_port(default:443);
var app_info = vcf::get_app_info(app:'Prime Infrastructure', port:port, webapp:TRUE);
var constraints = [{'min_version':'3.5', 'fixed_version':'3.9'}];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_NOTE
);
