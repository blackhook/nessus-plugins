#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(124119);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/18");

  script_cve_id("CVE-2018-7117");
  script_bugtraq_id(107857);

  script_name(english:"iLO 5 < 1.40 Cross Site Scripting (XSS) Vulnerability");
  script_summary(english:"Checks version of HP Integrated Lights-Out (iLO).");
  script_set_attribute(attribute:"synopsis", value:
"The remote HP Integrated Lights-Out (iLO) server's web interface is
affected by a cross site scripting (XSS) vulnerability.") ;
  script_set_attribute(attribute:"description", value:
"A cross-site scripting (XSS) vulnerability exists in HP Integrated Lights-Out 5 (iLO 5) due to improper validation of
user-supplied input before returning it to users. An unauthenticated, remote attacker can exploit this, by convincing
a user to click a specially crafted URL, to execute arbitrary script code in a user's browser session.");
  # https://support.hpe.com/hpsc/doc/public/display?docLocale=en_US&docId=emr_na-hpesbhf03907en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5132863");
  script_set_attribute(attribute:"solution", value:
"Upgrade firmware of HP Integrated Lights-Out 5 (iLO 5) to 1.40, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7117");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/17");

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

var constraints = [{'generation' : '5', 'fixed_version' : '1.40'}];
vcf::ilo::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
