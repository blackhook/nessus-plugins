#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106625);
  script_version("1.3");
  script_cvs_date("Date: 2019/01/02 16:37:56");

  script_cve_id("CVE-2010-0295");
  script_bugtraq_id(38036);

  script_name(english:"lighttpd < 1.4.26 or 1.5.0 Denial of Service");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of lighttpd running on the remote
host is prior to 1.4.26 or is 1.5.0. It is, therefore, affected by the following
vulnerabilities :

  - lighttpd allocates a buffer for each read operation which allows
    remote attackers to cause a denial of service (memory consumption)
    by breaking a request into small pieces that are sent at a slow rate.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.lighttpd.net/2015/7/26/1.4.36/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to lighttpd version 1.4.26. Alternatively, apply the
vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lighttpd:lighttpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("lighttpd_detect.nasl");
  script_require_keys("installed_sw/lighttpd", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_install_count(app_name:"lighttpd", exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE);
install = get_single_install(app_name:"lighttpd", port:port, exit_if_unknown_ver:TRUE);

version = install["version"];
if (ver_compare(ver:version, fix:"1.4.26", strict:TRUE) < 0)
{
  report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.4.26\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
  exit(0);
}
else if (version == "1.5.0")
{
  # No fix on this version line
  report =
      '\n  Installed version : ' + version + '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
  exit(0);
}
else
{
  audit(AUDIT_LISTEN_NOT_VULN, "lighttpd", port, version);
}
