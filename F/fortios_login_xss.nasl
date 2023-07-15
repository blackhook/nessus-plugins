#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90314);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/17");

  script_bugtraq_id(84429);

  script_name(english:"Fortinet FortiOS Redirect Parameter Multiple Vulnerabilities");
  script_summary(english:"Attempts to execute XSS attack.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Fortinet FortiOS that is
affected by the following vulnerabilities :

  - An open redirect vulnerability exists due to improper
    validation of user-supplied input before using it in
    redirects. An attacker can exploit this, via a specially
    crafted link, to redirect a victim to an arbitrary
    malicious website.

  - A cross-site scripting (XSS) vulnerability exists due to
    improper validation of user-supplied input to the
    parameter used to govern redirects. An attacker can
    exploit this, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2016/Mar/68");
  script_set_attribute(attribute:"solution", value:"Upgrade to Fortinet FortiOS version 5.0.13 / 5.2.3 / 5.4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("url_func.inc");
include("webapp_func.inc");
include('vcf.inc');
include('vcf_extras_fortios.inc');

var app = "Fortigate";

# Even though this is a remote check, the following
# should still be gathered in detection to verify
# that this is a FortiOS device. The default login
# page does not have enough unique characteristics to
# accomplish this.

version = get_kb_item_or_exit("Host/Fortigate/version");
model = get_kb_item_or_exit("Host/Fortigate/model");

port = get_http_port(default:80);

vcf::fortios::verify_product_and_model(product_name: app);

token = SCRIPT_NAME + unixtime();
xss = "javascript:alert('" + token + "');";

exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list('login'),
  cgi      : '',
  qs       : 'redir=' + urlencode(str:xss),
  pass_str : token,
  pass_re  : 'var'
);

if (!exploit) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:'/', port:port));
