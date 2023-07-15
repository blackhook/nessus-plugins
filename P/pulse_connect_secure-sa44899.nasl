#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154449);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id("CVE-2021-22965");
  script_xref(name:"IAVA", value:"2021-A-0498-S");

  script_name(english:"Pulse Connect Secure < 9.1R12.1 DoS (SA44899)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Pulse Connect Secure running on the remote host is prior to
9.1R12.1. It is, therefore, affected by a denial of service (DoS) vulnerability. A remote, unauthenticated attacker can
exploit this, by sending a malformed request to the device, in order to affect availability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44899");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pulse Connect Secure version 9.1R12.1, 9.1 R13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22965");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulsesecure:pulse_connect_secure");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pulse_connect_secure_detect.nbin");
  script_require_keys("installed_sw/Pulse Connect Secure");

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('vcf_extras.inc');

var port = get_http_port(default:443, embedded:TRUE);
var app_info = vcf::pulse_connect_secure::get_app_info(app:'Pulse Connect Secure', port:port, full_version:TRUE, webapp:TRUE);

# from https://www.ivanti.com/support/product-documentation
# https://help.ivanti.com/ps/help/en_US/PCS/9.1R12.1/rn/landingpage.htm
# 9.1R12.1 is 9.1.12.15299
var constraints = [
 {'fixed_version':'9.1.12.15299', 'fixed_display':'9.1R12.1 (Build 15299) / 9.1R13 (Build 15339)'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);

