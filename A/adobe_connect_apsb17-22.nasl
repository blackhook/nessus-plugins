#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101395);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-3101", "CVE-2017-3102", "CVE-2017-3103");
  script_bugtraq_id(99517, 99518, 99521);

  script_name(english:"Adobe Connect < 9.6.2 Multiple Vulnerabilities (APSB17-22)");
  script_summary(english:"Checks the version of Adobe Connect.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Connect running on the remote host is prior to
9.6.2. It is, therefore, affected by multiple vulnerabilities :

  - A clickjacking vulnerability exists due to a failure to
    prevent concealing hyperlinks beneath legitimate,
    clickable content using transparent opaque overlays. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a website with malicious
    content, to trick users into performing unintended
    actions. (CVE-2017-3101)

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist due to improper validation of user-supplied input
    before returning it to users. An unauthenticated, remote
    attacker can exploit these, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (CVE-2017-3102, CVE-2017-3103)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/connect/apsb17-22.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Connect version 9.6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3101");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:connect");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_connect_detect.nbin");
  script_require_keys("installed_sw/Adobe Connect");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("http.inc");
include("vcf.inc");

app = "Adobe Connect";
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:80);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
      { "max_version" : "9.6.1", "fixed_version" : "9.6.2" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
