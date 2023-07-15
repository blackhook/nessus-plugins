#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122032);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/18");

  script_cve_id("CVE-2018-7078", "CVE-2018-7101");

  script_name(english:"iLO 4 < 2.60 / iLO 5 < 1.30 Multiple Vulnerabilities");
  script_summary(english:"Checks version of HP Integrated Lights-Out (iLO).");

  script_set_attribute(attribute:"synopsis", value:
"The remote HP Integrated Lights-Out (iLO) server's web interface is
affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version number, the remote HP Integrated Lights-Out
(iLO) server is affected by multiple vulnerabilities:

  - A remote command execution vulnerability exists in HP Integrated 
  Lights-Out (iLO) server due to an unspecified reason. An unauthenticated,
  remote attacker can exploit this to bypass authentication and execute 
  arbitrary commands on the server (CVE-2018-7078).
  
  - A denial of service (DoS) vulnerability exists in HP Integrated 
  Lights-Out (iLO) server due to unspecified reason.
  An unauthenticated, remote attacker can exploit this 
  issue to cause the application to stop responding (CVE-2018-7101).");
  # https://support.hpe.com/hpsc/doc/public/display?docLocale=en_US&docId=emr_na-hpesbhf03844en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ddd05ce");
  # https://support.hpe.com/hpsc/doc/public/display?docLocale=en_US&docId=emr_na-hpesbhf03875en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?399330ab");
  script_set_attribute(attribute:"solution", value:
"For HP Integrated Lights-Out (iLO) 4 upgrade firmware to 2.60 or later. 
For iLO 5, upgrade firmware to 1.30 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7078");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ilo_detect.nasl");
  script_require_keys("www/ilo", "ilo/generation", "ilo/firmware");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('vcf_extras.inc');

var port = get_http_port(default:80, embedded:TRUE);
var app_info = vcf::get_app_info(app:'ilo', port:port, webapp:TRUE);
vcf::ilo::check_superdome(audit:TRUE);

var constraints = [
  {'generation': '4', 'fixed_version' : '2.60'},
  {'generation': '5', 'fixed_version' : '1.30'},
  {'moonshot': TRUE,  'fixed_version' : '1.58'}
];
vcf::ilo::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
