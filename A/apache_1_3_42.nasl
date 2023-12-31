#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44589);
  script_version("1.17");
  script_cvs_date("Date: 2018/11/15 20:50:25");

  script_cve_id("CVE-2010-0010");
  script_bugtraq_id(37966);
  script_xref(name:"Secunia", value:"38319");

  script_name(english:"Apache 1.3.x < 1.3.42 mod_proxy Integer Overflow");
  script_summary(english:"Checks the Apache version in Server response header.");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by an integer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 1.3.x running on the
remote host is prior 1.3.42. It is, therefore, potentially affected
by an integer overflow vulnerability in the mod_proxy Apache module.
A remote attacker can exploit this to cause a denial of service
condition or to execute arbitrary code.

Note that successful exploitation is possible only on platforms where
sizeof(int) < sizeof(long), such as 64-bit architectures. 

Also note that version 1.3.42 is the final release of Apache 1.3.");
  script_set_attribute(attribute:"see_also", value:"http://site.pi3.com.pl/adv/mod_proxy.txt" );
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2010/Jan/584" );
  # http://web.archive.org/web/20100515000000*/http://httpd.apache.org/dev/dist/CHANGES_1.3.42
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b8a4a59" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 1.3.42 or later. Alternatively, disable
mod_proxy."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);
  script_set_attribute(attribute:"vuln_publication_date", value: "2010/01/27");
  script_set_attribute(attribute:"patch_publication_date", value: "2010/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value: "2010/02/11");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2018 Tenable Network Security, Inc.");

  script_dependencies("apache_http_version.nasl", "proxy_use.nasl");
  script_require_keys("installed_sw/Apache");
  script_require_ports("Services/www", 80, 3128, 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("install_func.inc");

get_install_count(app_name:"Apache", exit_if_zero:TRUE);
port =  get_kb_item("Services/http_proxy");
if (!port)
{
  if (get_port_state(3128)) port = 3128;
  else port = 8080;
}
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");

install = get_single_install(app_name:"Apache", port:port, exit_if_unknown_ver:TRUE);

# Check if we could get a version first,  then check if it was
# backported
version = get_kb_item_or_exit('www/apache/'+port+'/version', exit_code:1);
backported = get_kb_item_or_exit('www/apache/'+port+'/backported', exit_code:1);

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "Apache");
source = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

# Check if the version looks like either ServerTokesn Major/Minor
# was used

if (version =~ '^1(\\.3)?$') exit(1, "The banner from the Apache server listening on port "+port+" - "+source+" - is not granular enough to make a determination.");
if (version !~ "^\d+(\.\d+)*$") exit(1, "The version of Apache listening on port " + port + " - " + version + " - is non-numeric and, therefore, cannot be used to make a determination.");
if (version =~ '^1\\.3' && ver_compare(ver:version, fix:'1.3.42') == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source + 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.3.42\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);
