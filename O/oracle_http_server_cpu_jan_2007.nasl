#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17730);
  script_cvs_date("Date: 2018/11/15 20:50:25");
  script_version("1.6");

  script_cve_id("CVE-2007-0279", "CVE-2007-0280", "CVE-2007-0281", "CVE-2007-0282");
  script_bugtraq_id(22083);

  script_name(english:"Oracle HTTP Server (January 2007 CPU)");
  script_summary(english:"Checks version in Server response header");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by multiple unspecified
vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Oracle HTTP Server installed
on the remote host is potentially affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2007 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/technetwork/topics/security/cpujan2007-101493.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6333510");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");

  script_dependencies("oracle_http_server_version.nasl");
  script_require_keys("www/oracle");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

# Only PCI considers this an issue.
if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

port = get_http_port(default:80);

# Make sure this is Oracle.
get_kb_item_or_exit("www/"+port+"/oracle");

# Get version information from the KB.
version = get_kb_item_or_exit("www/oracle/"+port+"/version", exit_code:1);
source = get_kb_item_or_exit("www/oracle/"+port+"/source", exit_code:1);

# Check if the remote server is affected. There is a patch in the CPU
# for each one of these versions of Oracle Application Server. No
# other versions can be patched by this CPU.
if (
  (version !~ "^9\.0\.4\.[1-3]") &&
  (version !~ "^10\.1\.2\.0\.[0-2]") &&
  (version !~ "10\.1\.2\.[1-2]\.0") &&
  (version !~ "10.1.3.[0-1].0")
) exit(0, "The Oracle Application Server " + version + " install listening on port " + port + " is not affected.");

if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
