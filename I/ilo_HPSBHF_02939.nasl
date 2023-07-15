#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(122188);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/18");

  script_cve_id("CVE-2013-4842", "CVE-2013-4843");
  script_bugtraq_id(63689, 63691);

  script_name(english:"iLO 3 < 1.65 / iLO 4 < 1.32 Multiple Vulnerabilities");
  script_summary(english:"Checks version of HP Integrated Lights-Out (iLO).");

  script_set_attribute(attribute:"synopsis", value:
"The remote HP Integrated Lights-Out (iLO) server's web interface is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the firmware of Integrated Lights-Out
running on the remote web server is iLO 3 prior to 1.65 or iLO 4 
prior to 1.32. It is, therefore, affected by multiple vulnerabilities:
  - A cross-site scripting (XSS) vulnerability exists due to improper
  validation of user-supplied input before returning it to users. 
  An unauthenticated, remote attacker can exploit this, by convincing
  a user to click a specially crafted URL, to execute arbitrary script
  code in a user's browser session (CVE-2013-4842).

  - An information disclosure vulnerability exists in Integrated 
  Lights-Out (iLO) 3 & 4 due to an undisclosed vulnerability. 
  An unauthenticated, remote attacker can exploit this to disclose
  potentially sensitive information (CVE-2013-4843).");
  # https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c03996804&docLocale=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aaf46ad1");
  script_set_attribute(attribute:"solution", value:
"For iLO 3, upgrade firmware to 1.65 or later. 
 For iLO 4, upgrade firmware to 1.32 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4843");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/14");

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

var constraints = [
  {'generation' : '3', 'fixed_version' : '1.65'}, 
  {'generation' : '4', 'fixed_version' : '1.32'}
];
vcf::ilo::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

