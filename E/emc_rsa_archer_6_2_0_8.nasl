#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107222);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2018-1219", "CVE-2018-1220");

  script_name(english:"EMC RSA Archer < 6.2.0.8 Multiple Vulnerabilities");
  script_summary(english:"Checks for the product and version in the login page.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of EMC RSA Archer running on the remote web server is
prior to 6.2.0.8. It is, therefore, affected by multiple
vulnerabilities. See advisory for details.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2018/Mar/12");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC RSA Archer version 6.2.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1220");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:rsa_archer_egrc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_rsa_archer_detect.nbin");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

app_name = "EMC RSA Archer";
port = get_http_port(default:80);

app = vcf::get_app_info(app:app_name, webapp:TRUE, port:port);

# 6.2.0.8 is ArcherVersion 6.2.800.1006
fix = "6.2.0.8";
vuln = FALSE;

if(app.version =~ "^[0-5]\." || app.version =~ "^6\.[01]\.")
  vuln = TRUE;
else if (app.version =~ "^6\.2\." && ver_compare(ver:app.version, fix:"6.2.800", strict:FALSE) < 0)
  vuln = TRUE;

if(vuln)
  vcf::report_results(app_info:app, fix:fix, severity:SECURITY_WARNING);
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, build_url(port:port, qs:app.path), app.version);
