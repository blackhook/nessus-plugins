#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45004);
  script_cvs_date("Date: 2018/11/15 20:50:25");
  script_version("1.37");

  script_cve_id(
    "CVE-2007-6750",
    "CVE-2009-3555",
    "CVE-2010-0408",
    "CVE-2010-0425",
    "CVE-2010-0434"
  );
  script_bugtraq_id(21865, 36935, 38491, 38494, 38580);
  script_xref(name:"Secunia", value:"38776");

  script_name(english:"Apache 2.2.x < 2.2.15 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.2.x running on the
remote host is prior to 2.2.15. It is, therefore, potentially affected
by multiple vulnerabilities :

  - A TLS renegotiation prefix injection attack is possible. 
    (CVE-2009-3555)

  - The 'mod_proxy_ajp' module returns the wrong status code
    if it encounters an error which causes the back-end 
    server to be put into an error state. (CVE-2010-0408)

  - The 'mod_isapi' attempts to unload the 'ISAPI.dll' when
    it encounters various error states which could leave
    call-backs in an undefined state. (CVE-2010-0425)

  - A flaw in the core sub-request process code can lead to
    sensitive information from a request being handled by 
    the wrong thread if a multi-threaded environment is
    used. (CVE-2010-0434)

  - Added 'mod_reqtimeout' module to mitigate Slowloris
    attacks. (CVE-2007-6750)"
  );
  script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_22.html");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=48359");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.2.15");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache version 2.2.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(200, 310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2018 Tenable Network Security, Inc.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("installed_sw/Apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

get_install_count(app_name:"Apache", exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:"Apache", port:port, exit_if_unknown_ver:TRUE);

# Check if we could get a version first, then check if it was
# backported
version = get_kb_item_or_exit('www/apache/'+port+'/version', exit_code:1);
backported = get_kb_item_or_exit('www/apache/'+port+'/backported', exit_code:1);

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "Apache");
source = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

# Check if the version looks like either ServerTokens Major/Minor
# was used
if (version =~ '^2(\\.2)?$') exit(1, "The banner from the Apache server listening on port "+port+" - "+source+" - is not granular enough to make a determination.");
if (version !~ "^\d+(\.\d+)*$") exit(1, "The version of Apache listening on port " + port + " - " + version + " - is non-numeric and, therefore, cannot be used to make a determination.");
if (version =~ '^2\\.2' && ver_compare(ver:version, fix:'2.2.15') == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.2.15\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);
