#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(54646);
  script_cvs_date("Date: 2018/11/15 20:50:25");
  script_version("1.18");

  script_cve_id("CVE-2011-1928");
  script_bugtraq_id(47929);
  script_xref(name:"Secunia", value:"44661");

  script_name(english:"Apache 2.2.x < 2.2.18 APR apr_fnmatch DoS");
  script_summary(english:"Checks version in Server response header");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by a denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.2.x running on the
remote host is 2.2.18. It is, therefore, affected by a denial of
service vulnerability due to an error in the fnmatch implementation in
'apr_fnmatch.c' in the bundled Apache Portable Runtime (APR) library. 

Successful exploitation of this vulnerability requires that
'mod_autoindex' be enabled. 

Note that the remote web server may not actually be affected by this
vulnerability. Nessus did not try to determine whether the affected
module is in use or to check for the issue itself.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.2.19");
  # http://mail-archives.apache.org/mod_mbox/www-announce/201105.mbox/%3C4DD55076.1060005@apache.org%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4fba9e29");
  # http://mail-archives.apache.org/mod_mbox/www-announce/201105.mbox/%3C4DD92D02.70000@apache.org%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7cc040c");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=51219");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.2.19 or later. Alternatively, ensure that
the 'IndexOptions' configuration option is set to 'IgnoreClient'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/25");
  script_set_attribute(attribute:"plugin_type", value: "remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");

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

vuln_ver  = '2.2.18';
fixed_ver = '2.2.19';
if (version == vuln_ver)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_ver + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);
