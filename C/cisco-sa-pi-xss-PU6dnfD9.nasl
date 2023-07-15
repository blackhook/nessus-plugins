#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170967);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/03");

  script_cve_id("CVE-2023-20068");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd56799");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cisco-pi-xss-PU6dnfD9");

  script_name(english:"Cisco Prime Infrastructure Reflected XSS (cisco-sa-cisco-pi-xss-PU6dnfD9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web-based management interface of Cisco Prime Infrastructure Software could allow an
unauthenticated, remote attacker to conduct a reflected cross-site scripting (XSS) attack against a user of
the interface on an affected device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  # https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-cisco-pi-xss-PU6dnfD9.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bde2b8a0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd56799");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwd56799");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20068");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_infrastructure");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_infrastructure_detect.nbin");
  script_require_keys("installed_sw/Prime Infrastructure");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var port = get_http_port(default:443);
var app_info = vcf::get_app_info(app:'Prime Infrastructure', port:port, webapp:TRUE);
var constraints = [{'min_version':'0.0', 'fixed_version':'3.10.3'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{'xss':TRUE});
