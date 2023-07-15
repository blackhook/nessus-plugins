#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159708);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/13");

  script_cve_id("CVE-2022-24681");
  script_xref(name:"IAVA", value:"2022-A-0139-S");

  script_name(english:"ManageEngine ADSelfService Plus < build 6121 XSS");

  script_set_attribute(attribute:"synopsis", value:
"A web application is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the ManageEngine ADSelfService Plus application running on the remote host is
prior to build 6121. It is, therefore, affected by a cross-site scripting vulnerability affecting the welcome name
attribute on the Reset Password, Unlock Account and User Must Change Password screens.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported build
number.");
  # https://www.manageengine.com/products/self-service-password/kb/CVE-2022-24681.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d4d24c4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ADSelfService Plus build 6121 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24681");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_adselfservice_plus");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_adselfservice_detect.nasl");
  script_require_keys("installed_sw/ManageEngine ADSelfService Plus");
  script_require_ports("Services/www", 8888);

  exit(0);
}

include('vcf.inc');
include('vcf_extras_zoho.inc');
include('http.inc');

var app, app_info, constraints, port;

app = 'ManageEngine ADSelfService Plus';

port = get_http_port(default:8888);

app_info = vcf::zoho::fix_parse::get_app_info(
  app: app,
  port:  port,
  webapp: TRUE
);

constraints = [
  { 'fixed_version':'6121', 'fixed_display':'build 6121'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);

