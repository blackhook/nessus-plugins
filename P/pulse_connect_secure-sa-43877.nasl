#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135694);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-20808");
  script_bugtraq_id(109346);
  script_xref(name:"IAVB", value:"2019-B-0049-S");

  script_name(english:"Pulse Connect Secure XSS (SA3877)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Pulse Connect Secure running on the remote host is 8.3Rx prior 
to 8.3R3 It is, therefore, affected by a cross-site scripting vulnerability in rd.cgi due to improper header
sanitization. An unauthenticated, remote attacker can exploit this, by convincing a user to click a specially crafted
URL, to execute arbitrary script code in a user's browser session.");
  # https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA43877
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d485b8fe");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pulse Connect Secure version 8.3R3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20808");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulsesecure:pulse_connect_secure");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pulse_connect_secure_detect.nbin");
  script_require_keys("installed_sw/Pulse Connect Secure");

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('vcf_extras.inc');

port = get_http_port(default:443, embedded:TRUE);
app_info = vcf::pulse_connect_secure::get_app_info(app:'Pulse Connect Secure', port:port, full_version:TRUE, webapp:TRUE);

constraints = [
 {'min_version':'8.3.0', 'fixed_version':'8.3.3.59199.1', 'fixed_display':'8.3R3'}
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:true});
