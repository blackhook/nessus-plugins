#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101304);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-4998",
    "CVE-2017-4999",
    "CVE-2017-5000",
    "CVE-2017-5001",
    "CVE-2017-5002"
  );
  script_bugtraq_id(99354);

  script_name(english:"EMC RSA Archer < 6.2.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks for the product and version in the login page.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of EMC RSA Archer running on the remote web server is
prior to 6.2.0.2. It is, therefore, affected by multiple
vulnerabilities :

  - A cross-site request forgery (XSRF) vulnerability exists
    when handling HTTP requests due to a failure to require
    multiple steps, explicit confirmation, or a unique token
    when performing sensitive actions. An authenticated,
    remote attacker can exploit this, by convincing a user
    to follow a specially crafted link, to execute
    unauthorized actions on behalf of the user with the
    user's level of privileges. (CVE-2017-4998)

  - An authorization bypass vulnerability exists in
    Discussion Forum Messages component due to improper
    handling of input passed via user-controlled keys. An
    authenticated, remote attacker can exploit this to gain
    elevated privileges and view other users' discussion
    forum messages. (CVE-2017-4999)

  - Multiple information disclosure vulnerabilities exist in
    error messages that allow an authenticated, remote
    attacker to gain potentially sensitive information.
    (CVE-2017-5000, CVE-2017-5001)

  - A cross-side redirection vulnerability exists due to
    improper validation of user-supplied input before
    returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted link,
    to redirect an unsuspecting user from the intended
    trusted website to an arbitrary website of the
    attacker's choosing, which can then be used to conduct
    further attacks. (CVE-2017-5002)");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2017/Jun/49");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC RSA Archer version 6.2.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4998");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/07");

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
flags = make_array("xsrf", TRUE);
fix = "6.2.0.2";
vuln = FALSE;

if(app.version =~ "^5" || app.version =~ "^6\.1")
  vuln = TRUE;
else if (app.version =~ "^6\.2" && ver_compare(ver:app.version, fix:"6.2.200", strict:FALSE) < 0)
  vuln = TRUE;

if(vuln)
  vcf::report_results(app_info:app, fix:fix, severity:SECURITY_WARNING, flags:flags);
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, build_url(port:port, qs:app.path));
