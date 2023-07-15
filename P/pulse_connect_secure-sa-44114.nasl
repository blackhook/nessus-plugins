#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125628);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-11213");
  script_xref(name:"CERT", value:"192371");

  script_name(english:"Pulse Connect Secure Insecure Cookie Handling (SA44114)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an insecure cookie handling flaw.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Pulse Connect
Secure running on the remote host is is prior to 8.1R14, 8.3R7, or
9.0R3 and thus, is affected by an error related to handling session
cookies that allows an attacker to access session cookies and spoof
sessions.");
  # https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44114
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b3e709e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 8.1R14, 8.3R7, 9.0R3, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11213");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulsesecure:pulse_connect_secure");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
 {'min_version':'9.0.0', 'fixed_version':'9.0.3.64003', 'fixed_display':'9.0R3'},
 {'min_version':'8.3.0', 'fixed_version':'8.3.7.65013', 'fixed_display':'8.3R7'},
 {'min_version':'8.1.0', 'fixed_version':'8.1.14.59737', 'fixed_display':'8.1R14'},
 # Everything else and suggest upgrade to latest
 # '8.1R0' is not a version, but is used as a ceiling
 {'min_version' : '0.0', 'fixed_version':'8.1.0', 'fixed_display' : '9.0R3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
