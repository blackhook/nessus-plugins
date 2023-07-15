#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(142742);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/28");

  script_cve_id("CVE-2020-24442", "CVE-2020-24443");
  script_xref(name:"IAVB", value:"2020-B-0067-S");

  script_name(english:"Adobe Connect < 11.0.5 XSS (APSB20-69)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Connect running on the remote host is prior to 11.0.5. It is, therefore, affected by multiple 
cross-site scripting (XSS) vulnerabilities due to improper validation of user-supplied input before returning it to 
users. An unauthenticated, remote attacker can exploit these, by convincing a user to click a specially crafted URL, 
to execute arbitrary script code in a user's browser session.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/connect/apsb20-69.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Connect version 11.0.5 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24443");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:connect");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_connect_detect.nbin");
  script_require_keys("installed_sw/Adobe Connect");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('http.inc');
include('vcf.inc');

port = get_http_port(default:80);
app_info = vcf::get_app_info(app:'Adobe Connect', port:port, webapp:TRUE);

constraints = [{'max_version': '11.0', 'fixed_version' : '11.0.5'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
