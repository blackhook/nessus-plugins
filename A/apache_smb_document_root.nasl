#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17695);
  script_version("1.7");
  script_cvs_date("Date: 2018/11/15 20:50:25");

  script_cve_id("CVE-2007-6514");
  script_bugtraq_id(26939);

  script_name(english:"Apache Mixed Platform AddType Directive Information Disclosure");
  script_summary(english:"Checks for Apache");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache server is vulnerable to an information disclosure
attack.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running Apache.  When Apache runs on a
Unix host with a document root on a Windows SMB share, remote,
unauthenticated attackers could obtain the unprocessed contents of the
directory.  For example, requesting a PHP file with a trailing
backslash could display the file's source instead of executing it.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb25db1c");

  script_set_attribute(attribute:"solution", value:
"Ensure that the document root is not located on a Windows SMB
share.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200);
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");

  script_dependencie("apache_http_version.nasl");
  script_require_keys("installed_sw/Apache", "Settings/PCI_DSS");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

# Only PCI considers this an issue.
if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

get_install_count(app_name:"Apache", exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:"Apache", port:port, exit_if_unknown_ver:TRUE);

# All versions are vulnerable.
source = get_kb_item_or_exit("www/apache/"+port+"/pristine/source", exit_code:1);
version = get_kb_item_or_exit("www/apache/"+port+"/pristine/version", exit_code:1);

report =
  '\n  Version source    : ' + source +
  '\n  Installed version : ' + version +
  '\n';
security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
