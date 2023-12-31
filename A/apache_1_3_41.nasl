#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31408);
  script_version("1.30");
  script_cvs_date("Date: 2018/11/15 20:50:25");

  script_cve_id("CVE-2007-3847","CVE-2007-5000","CVE-2007-6388","CVE-2008-0005");
  script_bugtraq_id(25489, 26838, 27234, 27237);

  script_name(english:"Apache 1.3.x < 1.3.41 Multiple Vulnerabilities (DoS, XSS)");
  script_summary(english:"Checks version in Server response header.");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by several issues.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 1.3.x running on the
remote host is prior to 1.3.41. It is, therefore, affected by multiple
vulnerabilities :

  - A denial of service issue in mod_proxy when parsing
    date-related headers. (CVE-2007-3847)

  - A cross-site scripting issue involving mod_imap.
    (CVE-2007-5000).

  - A cross-site scripting issue in mod_status involving 
    the refresh parameter. (CVE-2007-6388)

  - A cross-site scripting issue using UTF-7 encoding
    in mod_proxy_ftp exists because it does not 
    define a charset. (CVE-2008-0005)

Note that the remote web server may not actually be affected by these
vulnerabilities. Nessus did not try to determine whether the affected
modules are in use or to check for the issues themselves.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/archive/1/486167/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_1.3.41");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 1.3.41 or later. Alternatively, ensure that
the affected modules are not in use.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/07");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2008-2018 Tenable Network Security, Inc.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("installed_sw/Apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("install_func.inc");

get_install_count(app_name:"Apache", exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:"Apache", port:port, exit_if_unknown_ver:TRUE);

# Check if we could get a version first,  then check if it was
# backported
version = get_kb_item_or_exit('www/apache/'+port+'/version', exit_code:1);
backported = get_kb_item_or_exit('www/apache/'+port+'/backported', exit_code:1);

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "Apache");
source = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

if (report_paranoia < 2)
{
  if (!empty_or_null(install["modules"]) && "mod_status" >!< install["modules"] &&
      "mod_proxy" >!< install["modules"] && "mod_proxy_ftp" >!< install["modules"] &&
      "mod_imap" >!< install["modules"])
  {
    exit(0, "The affected modules do not appear to be installed on the Apache server on port "+port+".");
  }
}

# Check if the version looks like either ServerTokesn Major/Minor
# was used
if (version =~ '^1(\\.3)?$') exit(1, "The banner from the Apache server listening on port "+port+" - "+source+" - is not granular enough to make a determination.");

if (version !~ "^\d+(\.\d+)*$") exit(1, "The version of Apache listening on port " + port + " - " + version + " - is non-numeric and, therefore, cannot be used to make a determination.");
if (version =~ '^1\\.3' && ver_compare(ver:version, fix:'1.3.40') == -1)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.3.40\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);
