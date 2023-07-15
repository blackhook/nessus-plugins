#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(142596);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2020-5377");

  script_name(english:"Dell OpenManage Server Administrator Path Traversal (DSA-2020-172)");

  script_set_attribute(attribute:"synopsis", value:
"A web application hosted on the remote web server is affected by a
path traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Dell OpenManage Server Administrator (OMSA) running on
the remote host is affected by a path traversal vulnerability due to
improper sanitization of user-supplied input to a web API request. An
unauthenticated, remote attacker can exploit this, via a crafted
request, to gain file system access on the remote host.");
  # https://www.dell.com/support/article/en-us/sln322304/dsa-2020-172-dell-emc-openmanage-server-administrator-omsa-path-traversal-vulnerability?lang=en
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e2c8403");
  script_set_attribute(attribute:"solution", value:
"Install Dell EMC OpenManage Server Administrator 9.3.0.2 / 9.4.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5377");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:openmanage_server_administrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_openmanage.nasl");
  script_require_keys("www/dell_omsa");
  script_require_ports("Services/www", 1311);

  exit(0);
}

include('http.inc');
include('webapp_func.inc');

app = "Dell OpenManage Server Administrator";

# Exit if app is not detected on the host.
get_install_count(app_name:'dell_omsa', exit_if_zero:TRUE);

# Exit if app is not detected on this http port.
port = get_http_port(default:1311, embedded:TRUE);
install = get_single_install(app_name:'dell_omsa', port:port);
base_url = build_url(qs:install['dir'], port:port);

# .exe is not a valid file extension for the DownloadServlet servlet:
#
#     HashMap<Object, Object> hashMap1 = new HashMap<>();
#     hashMap1.put("file_1", "oma_\\d+.(log|html|zip)$");
#     hashMap1.put("file_2", "\\.*(\\.cer|\\.CER)$");
#     a.put("DownloadServlet", hashMap1);
url = '/DownloadServlet?file=some_file.exe';
res = http_send_recv3(
  port            : port,
  method          : 'GET',
  item            : url,
  exit_on_fail    : TRUE
);
# Patched server properly invokes
# security.web.SecurityTypeDefs.isValidURI() to checks the URL.
# It returns a 400 when seeing an invalid file extension in the
# 'file' URL parameter.
if(' 400 ' >< res[0])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, base_url);
#
# Vulnerable server has a logical error in
# security.web.PathManipulationFilter.doFilter(), resulting in
# security.web.SecurityTypeDefs.isValidURI() not being called to
# check the URL.
#
# The request continues getting processed, but since we are not
# authenticated, the server returns a 403.
else if(' 403 ' >< res[0])
{
  extra = 'Nessus was able to detect the issue by sending the' +
    ' following HTTP request to the remote host : ' +
    '\n' +
    '\n' +
    http_last_sent_request();

  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    extra      : extra 
  );
}
# Unexpected response status
else
  audit(AUDIT_RESP_BAD, port, 'an HTTP request. Unexpected HTTP response status ' + chomp(res[0]));
