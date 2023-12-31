#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64501);
  script_version("1.9");
  script_cvs_date("Date: 2018/09/17 21:46:53");

  script_cve_id("CVE-2012-5643", "CVE-2013-0189");
  script_bugtraq_id(56957, 57646);
  

  script_name(english:"Squid 2.x / 3.x < 3.1.23 / 3.2.6 / 3.3.0.3 cachemgr.cgi DoS");
  script_summary(english:"Checks version of Squid");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Squid running on the remote
host is 2.x or 3.x prior to 3.1.23 / 3.2.6 / 3.3.0.3.  The included
'cachemgr.cgi' tool reportedly lacks input validation, which could be
abused by any client able to access that tool to perform a denial of
service attack on the service host.

Note this fix is a result of an incomplete fix for CVE-2012-5643.
 
Further note that Nessus did not actually test for this issue, but
instead has relied on the version in the server's banner.");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2012_1.txt");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to Squid version 3.1.23 / 3.2.6 / 3.3.0.3 or later, or
apply the vendor-supplied patch. 

Alternatively, restrict access to this CGI or limit CGI memory
consumption via the host web server's configuration options.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0189");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");

  script_dependencies("squid_version.nasl");
  script_require_keys("www/squid", "Settings/ParanoidReport");
  script_require_ports("Services/http_proxy", 3128, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Build a list of ports from the 
list = get_kb_list("http_proxy/*/squid/version");
if (isnull(list)) audit(AUDIT_NOT_INST, "Squid");

# nb: banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vulnerable = FALSE;
not_vuln_list = make_list();

foreach item (keys(list))
{
  port = ereg_replace(pattern:'^http_proxy/([0-9]+)/squid/version', replace:'\\1', string:item);
  version = list[item];
  # Affected:
  # Squid 2.x all releases
  # Squid 3.0 all releases
  # Squid 3.1 < 3.1.23
  # Squid 3.2 < 3.2.6
  # Squid 3.3.0.x < 3.3.0.3
  if (
    version =~ "^2\." ||
    version =~ "^3\.0\." ||
    version =~ "^3\.1\.([0-9]|1[0-9]|2[0-2])([^0-9]|$)" ||
    version =~ "^3\.2\.[0-5]([^0-9]|$)" ||
    version =~ "^3\.3\.0\.[0-2]([^0-9]|$)"
  )
  {
    vulnerable = TRUE;
    if (report_verbosity > 0)
    {
      source = get_kb_item('http_proxy/'+port+'/squid/source');
      report = 
        '\n  Version source    : ' + source +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 3.1.23 / 3.2.6 / 3.3.0.3' + '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port:port);
  }
  else not_vuln_list = make_list(not_vuln_list, version + " on port " + port);
}

if (vulnerable) exit(0);
else
{
  installs = max_index(not_vuln_list);
  if (installs == 0) audit(AUDIT_NOT_INST, "Squid");
  else if (installs == 1)
    audit(AUDIT_INST_VER_NOT_VULN, "Squid", not_vuln_list[0]);
  else
    exit(0, "The Squid installs ("+ join(not_vuln_list, sep:", ") + ") are not affected.");
}
