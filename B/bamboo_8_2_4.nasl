#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165184);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2022-26136", "CVE-2022-26137");

  script_name(english:"Atlassian Bamboo < 7.2.10 / 8.0.x < 8.0.9 / 8.1.x < 8.1.4 / 8.2.x < 8.2.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Bamboo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Bamboo installed on the remote host is prior to 7.2.10, 8.0.x prior to 8.0.9, 8.1.x prior to
8.1.8 or 8.2.4. It is, therefore affected by multiple vulnerabilities:

 - A remote, unauthenticated attacker can bypass arbitrary Servlet Filters used by first and third party
   apps. The impact depends on which filters are used by each app and how the filters are used. Confirmed
   attacks include an authentication bypass on custom Servlet Filters used by third party apps and a
   cross-site scripting (XSS) attack on the Servlet Filter used to validate legitimate Atlassian Gadgets.
   (CVE-2022-26136)

 - A remote, unauthenticated attacker can cause additional Servlet Filters to be invoked when the application
   processes requests or responses. Confirmed attacks of this vulnerability include a cross-origin resource
   sharing bypass where an attacker that can trick a user into requesting a malicious URL can access the
   vulnerable application with the victim's permissions. (CVE-2022-26137)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/BAM-21795");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Bamboo version 7.2.10, 8.0.9, 8.1.8, 8.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26137");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:bamboo");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bamboo_detect.nbin");
  script_require_keys("installed_sw/bamboo");
  script_require_ports("Services/www", 8085);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var app = 'bamboo';
get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:8085);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '7.2.10' },
  { 'min_version' : '8.0', 'fixed_version' : '8.0.9'},
  { 'min_version' : '8.1', 'fixed_version' : '8.1.8'},
  { 'min_version' : '8.2', 'fixed_version' : '8.2.4'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{'xss':TRUE}
);
