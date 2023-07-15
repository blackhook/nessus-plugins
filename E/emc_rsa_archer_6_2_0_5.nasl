#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103818);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-8016",
    "CVE-2017-8025",
    "CVE-2017-14369",
    "CVE-2017-14370",
    "CVE-2017-14371",
    "CVE-2017-14372"
  );
  script_bugtraq_id(101195);

  script_name(english:"EMC RSA Archer < 6.2.0.5 Multiple Vulnerabilities");
  script_summary(english:"Checks for the product and version in the login page.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of EMC RSA Archer running on the remote web server is
prior to 6.2.0.5. It is, therefore, affected by multiple
vulnerabilities. See advisory for details.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2017/Oct/12");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC RSA Archer version 6.2.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8025");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:rsa_archer_egrc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_rsa_archer_detect.nbin");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

app_name="EMC RSA Archer";
port = get_http_port(default:80);
app = vcf::get_app_info(app:app_name, webapp:TRUE, port:port);
flags = make_array("xss", TRUE);
fix = "6.2.0.6";
vuln = FALSE;

if(app.version =~ "^5" || app.version =~ "^6\.1")
  vuln = TRUE;
else if (app.version =~ "^6\.2" && ver_compare(ver:app.version, fix:"6.2.500", strict:FALSE) < 0)
  vuln = TRUE;

if(vuln)
  vcf::report_results(app_info:app, fix:fix, severity:SECURITY_WARNING, flags:flags);
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, build_url(port:port, qs:app.path));
