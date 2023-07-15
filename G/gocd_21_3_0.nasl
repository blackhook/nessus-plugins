#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157066);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/25");

  script_name(english:"GoCD < 21.3.0 Path Traversal");

  script_set_attribute(attribute:"synopsis", value:
"The GoCD web application running on the remote host is affected by a directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The GoCD web application running on the remote host has the Business Continuity add-on enabled by default. It is,
therefore, affected by a directory traversal vulnerability due to an improper access restriction. An unauthenticated,
remote attacker can exploit this, by sending a URI that contains directory traversal characters, to disclose the contents
of files located outside of the server's restricted path.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.gocd.org/releases/#21-3-0");
  script_set_attribute(attribute:"see_also", value:"https://blog.sonarsource.com/gocd-pre-auth-pipeline-takeover");
  script_set_attribute(attribute:"solution", value:
"Update to GoCD 21.3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on in depth analysis of the vendor advisory by Tenable.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:thoughtworks:gocd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("gocd_web_detect.nbin");
  script_require_keys("installed_sw/GoCD");
  script_require_ports("Services/www", 8153);

  exit(0);
}

include('http.inc');
include('vcf.inc');

app_info = vcf::get_app_info(app:'GoCD', port:get_http_port(default:8153), webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [{'fixed_version' : '21.3.0' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
