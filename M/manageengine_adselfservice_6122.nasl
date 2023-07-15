#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172490);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/13");

  script_cve_id("CVE-2022-28810");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/03/28");

  script_name(english:"ManageEngine ADSelfService Plus < build 6122 Command Injection");

  script_set_attribute(attribute:"synopsis", value:
"A web application is affected by a command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the ManageEngine ADSelfService Plus application running on the remote host is
prior to build 6122. It is, therefore, affected by a command injection vulnerability which allows a remote authenticated
administrator to execute arbitrary operating OS commands as SYSTEM via the policy custom script feature. Due to the use
of a default administrator password, attackers may be able to abuse this functionality with minimal effort.
Additionally, a remote and partially authenticated attacker may be able to inject arbitrary commands into the custom
script due to an unsanitized password field.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported build
number.");
  # https://www.manageengine.com/products/self-service-password/advisory/CVE-2022-28810.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a99e2dc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ADSelfService Plus build 6122 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28810");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ManageEngine ADSelfService Plus Custom Script Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_adselfservice_plus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'fixed_version':'6122', 'fixed_display':'build 6122'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity: SECURITY_HOLE
);

