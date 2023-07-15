#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# It was modified by H D Moore to not crash the server during the test
#
# Supercedes MS01-033

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10685);
  script_version("1.52");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2001-0500",
    "CVE-2001-0506",
    "CVE-2001-0507",
    "CVE-2001-0508",
    "CVE-2001-0544",
    "CVE-2001-0545"
  );
  script_bugtraq_id(
    2690,
    2880,
    3190,
    3193,
    3194,
    3195
  );
  script_xref(name:"MSFT", value:"MS01-033");
  script_xref(name:"MSFT", value:"MS01-044");
  script_xref(name:"MSKB", value:"294774");
  script_xref(name:"MSKB", value:"297860");
  script_xref(name:"MSKB", value:"298340");
  script_xref(name:"MSKB", value:"300972");
  script_xref(name:"MSKB", value:"301625");
  script_xref(name:"MSKB", value:"304867");
  script_xref(name:"MSKB", value:"305359");

  script_name(english:"Microsoft IIS ISAPI Filter Multiple Vulnerabilities (MS01-044)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"There's a buffer overflow in the remote web server through
the ISAPI filter.
 
It is possible to overflow the remote web server and execute 
commands as user SYSTEM.

Additionally, other vulnerabilities exist in the remote web
server since it has not been patched.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2001/ms01-033");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2001/ms01-044");
  script_set_attribute(attribute:"solution", value:
"Apply the patches from the bulletins above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS01-033 Microsoft IIS 5.0 IDQ Path Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2001/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/06/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2001-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

# The attack starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
b = get_http_banner(port: port);
if ("IIS" >!< h ) exit(0);
   
     
w = http_send_recv3(method: "GET", port: port,
  item: "/x.ida?"+crap(length:220, data:"x")+"=x");
if (isnull(w)) exit(1, "the web server did not answer");
r = strcat(w[0], w[1], '\r\n', w[2]);

    # 0xc0000005 == "Access Violation"
    if ("0xc0000005" >< r)
    {
        security_hole(port);
    }

