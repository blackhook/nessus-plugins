#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67128);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-2765");
  script_bugtraq_id(60182);
  script_xref(name:"EDB-ID", value:"25852");

  script_name(english:"ModSecurity < 2.7.4 forceRequestBodyVariable Action Handling DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application firewall may be affected by a denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of ModSecurity installed on the
remote host is earlier than 2.7.4. It is, therefore, potentially
affected by a denial of service vulnerability. An error exists related
to handling the action 'forceRequestBodyVariable' that could allow an
HTTP request to cause a NULL pointer to be dereferenced and an
application crash.

Note that Nessus has not tested for this issue but has instead relied
only on the version in the server's banner.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/oss-sec/2013/q2/420");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ModSecurity version 2.7.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2765");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:modsecurity:modsecurity");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("modsecurity_http_version.nasl");
  script_require_keys("www/ModSecurity", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Make sure this is ModSecurity
get_kb_item_or_exit('www/'+port+'/modsecurity');
version = get_kb_item_or_exit('www/modsecurity/'+port+'/version', exit_code:1);
backported = get_kb_item_or_exit('www/modsecurity/'+port+'/backported', exit_code:1);

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "ModSecurity");

if (version == 'unknown') audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "ModSecurity", port);

fixed_ver = '2.7.4';
if (
  version =~ "^[01]\." ||
  version =~ "^2\.([0-6]|7\.[0-3])($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit('www/modsecurity/'+port+'/source', exit_code:1);

    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_ver + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "ModSecurity", port, version);
