#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(107227);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2017-5660");

  script_name(english:"Apache Traffic Server 6.x < 6.2.2 / 7.x < 7.1.2 Host Header and Line Folding Vulnerability");
  script_summary(english:"Checks the version of Apache Traffic Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote caching server is affected by an input-validation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache Traffic Server running
on the remote host is 6.x prior to 6.2.2 or 7.x prior to 7.1.2. It is,
therefore, affected by an input-validation vulnerability related to
handling 'Host' headers and line folding that allows a remote attacker
to cause the wrong host to be used.


Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  # https://lists.apache.org/thread.html/22d84783d94c53a5132ec89f002fe5165c87561a9428bcb6713b3c98@%3Cdev.trafficserver.apache.org%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2bec76e2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Traffic Server version 6.2.2, 7.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5660");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:traffic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_traffic_server_version.nasl", "npn_protocol_enumeration.nasl");
  script_require_keys("www/apache_traffic_server");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

app = 'Apache Traffic Server';
port = get_http_port(default:8080);

# Make sure this is Apache Traffic Server
get_kb_item_or_exit('www/'+port+'/apache_traffic_server');

# Check if we could get a version
version   = get_kb_item_or_exit('www/'+port+'/apache_traffic_server/version', exit_code:1);
source    = get_kb_item_or_exit('www/'+port+'/apache_traffic_server/source', exit_code:1);

# Is numeric
if (version !~ "^[0-9.]+$")
  audit(AUDIT_NONNUMERIC_VER, app, port, version);

# Is proper branch
if (version !~ "^[67]($|[^0-9])")
  audit(AUDIT_NOT_LISTEN, app + " 6.x / 7.x", port);

# Is granular enough
if (
  version =~ "^6(\.2)?$" ||
  version =~ "^7(\.1)?$"
)
  audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

if (
  (
    version =~ "^6\." &&
    ver_compare(ver:version, fix:'6.2.2', strict:FALSE) < 0
  )
  ||
  (
    version =~ "^7\." &&
    ver_compare(ver:version, fix:'7.1.2', strict:FALSE) < 0
  )
)
{
  report =
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 6.2.2 / 7.1.2' +
    '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port, version);
