#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(122095);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/18");

  script_cve_id("CVE-2017-12542");

  script_name(english:"iLO 4 < 2.53 Remote Code Execution Vulnerability");
  script_summary(english:"Checks version of HP Integrated Lights-Out (iLO).");

  script_set_attribute(attribute:"synopsis", value:
"The remote HP Integrated Lights-Out (iLO) server's web interface is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"A remote command execution vulnerability exists in Integrated 
Lights-Out 4 (iLO 4) due to a buffer overflow in the server's http 
connection handling code. An unauthenticated, remote attacker can 
exploit this to bypass authentication and execute arbitrary commands.");
  # https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03769en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd1b001e");
  script_set_attribute(attribute:"solution", value:
"Upgrade firmware of HP Integrated Lights-Out 4 (iLO 4) to 2.53, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12542");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/11");

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

var port = get_http_port(default:80, embedded: TRUE);
var app_info = vcf::get_app_info(app:'ilo', port:port, webapp:TRUE);
vcf::ilo::check_superdome(audit:TRUE);

var constraints = [{'generation': '4', 'fixed_version':'2.53'}];
vcf::ilo::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
