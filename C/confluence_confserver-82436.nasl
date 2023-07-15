#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172376);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_name(english:"Atlassian Confluence < 7.13.14 / 7.14.x < 7.19.6 / 7.20.x < 8.1.0 (CONFSERVER-82436)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence installed on the remote host is affected by an information disclosure
vulnerability in the Synchrony service. An unauthenticated, remote attacker can exploit this to view sensitive
information.

Note that Nessus has not tested for this issue but has instead relied only on Confluence's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-82436");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.13.14, 7.19.6, 8.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on an in-depth analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_detect.nasl");
  script_require_keys("installed_sw/confluence");
  script_require_ports("Services/www", 8080, 8090);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:80);
var app_info = vcf::get_app_info(app:'confluence', port:port, webapp:true);

var constraints = [
  { 'fixed_version' : '7.13.14' },
  { 'min_version' : '7.14.0', 'fixed_version' : '7.19.6' },
  { 'min_version' : '7.20.0', 'fixed_version' : '8.1.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
