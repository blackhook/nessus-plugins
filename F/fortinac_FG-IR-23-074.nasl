#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177588);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id("CVE-2023-33299");
  script_xref(name:"CEA-ID", value:"CEA-2023-0025");

  script_name(english:"Fortinet FortiNAC RCE (FG-IR-23-074)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of FortiNAC installed on the remote host is prior to 9.4.3. It is, therefore, affected by a vulnerability as
referenced in the FG-IR-23-074 advisory.

  - A deserialization of untrusted data in Fortinet FortiNAC below 7.2.1, below 9.4.3, below 9.2.8 and all
    earlier versions of 8.x allows attacker to execute unauthorized code or commands via specifically crafted
    request on inter-server communication port. Note FortiNAC versions 8.x will not be fixed. (CVE-2023-33299)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Update FortiNAC to version 7.2.2, 9.1.10, 9.2.8, 9.4.3, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-33299");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortinac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_fortinac_web_detect.nbin");
  script_require_keys("installed_sw/Fortinet FortiNAC");
  script_require_ports("Services/www", 8443);

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('vcf_extras_fortios.inc');

var port = get_http_port(default:8443);

var app_name = 'Fortinet FortiNAC';

var app_info = vcf::get_app_info(app:app_name, port:port, webapp:TRUE);

var constraints = [
  { 'min_version': '7.2.0', 'fixed_version' : '7.2.2' },
  { 'min_version': '8.3.0', 'fixed_version' : '9.1.10' },
  { 'min_version': '9.2.0', 'fixed_version' : '9.2.8' },
  { 'min_version': '9.4.0', 'fixed_version' : '9.4.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
