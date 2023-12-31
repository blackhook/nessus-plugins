#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90318);
  script_version("1.14");
  script_cvs_date("Date: 2019/11/19");

  script_cve_id("CVE-2015-5351");
  script_bugtraq_id(83330);

  script_name(english:"Apache Tomcat XSRF Token Disclosure");
  script_summary(english:"Checks for XSRF token disclosure.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Apache Tomcat web server is affected by an information
disclosure vulnerability in the index page of the Manager and Host
Manager applications. An unauthenticated, remote attacker can exploit
this vulnerability to obtain a valid cross-site request forgery (XSRF)
token during the redirect issued when requesting /manager/ or
/host-manager/. This token can be utilized by an attacker to construct
an XSRF attack.

Note that there are reportedly several additional vulnerabilities;
however, Nessus has not tested for these.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2016/Feb/148");
  # http://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.0.M3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77a5c04a");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.0.32");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.68");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 7.0.68 / 8.0.32 / 9.0.0.M3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5351");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl");
  script_require_keys("installed_sw/Apache Tomcat", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("webapp_func.inc");
include("misc_func.inc");
include("http.inc");
include("tomcat_version.inc");

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

get_install_count(app_name:"Apache Tomcat", exit_if_zero:TRUE);
port = get_http_port(default:8080);
install = get_single_install(app_name:"Apache Tomcat", port:port, exit_if_unknown_ver:TRUE);

# Check version first, as the patch simply prevents the session from being
# used, so in some configurations the nonce can still be generated
# although it would be useless in an attack on a patched version
ver  = install["version"];
if (ver =~ "^7(\.0)?$")
  audit(AUDIT_VER_NOT_GRANULAR, "Apache Tomcat", port, ver);

if (ver =~ "^7\.0")
  fix = "7.0.68";
else if (ver =~ "^8\.0")
  fix = "8.0.32";
else if (ver =~ "^9\.0")
  fix = "9.0.0.M3";
else
  audit(AUDIT_LISTEN_NOT_VULN, "Apache Tomcat", port);

if (tomcat_ver_cmp(ver:ver, fix: fix, same_branch:0) >=0)
  audit(AUDIT_LISTEN_NOT_VULN, "Apache Tomcat", port);

urls = make_list("manager/", "host-manager/");
vuln = FALSE;

foreach url (urls)
{
  res = http_send_recv3(
    port            : port,
    method          : "GET",
    item            : "/" + url,
    exit_on_fail    : TRUE
  );

  if (res[0] =~ "^HTTP/[0-9]\.[0-9] 30[1237]")
  {
    headers = parse_http_headers(status_line:res[0], headers:res[1]);
      if (isnull(headers)) audit(AUDIT_WEB_NO_SERVER_HEADER, port);

    token = pregmatch(
      string  : headers['location'],
      pattern : "^.*CSRF_NONCE=(.*)$",
      icase   : TRUE
    );

    if (!empty_or_null(token[1]))
    {
      vuln = TRUE;
      exploit = build_url(qs:url, port:port);
      break;
    }
  }
}
if (!vuln)
  audit(AUDIT_LISTEN_NOT_VULN, "Apache Tomcat", port);

security_report_v4(
  port      : port,
  severity  : SECURITY_WARNING,
  generic   : TRUE,
  xsrf      : TRUE,
  request   : make_list(exploit),
  output    : res[0] + res[1],
  rep_extra : '\nThe XSRF token found is : "'+token[1]+'"'
);
