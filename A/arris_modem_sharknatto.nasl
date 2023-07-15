#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102916);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-10793",
    "CVE-2017-14115",
    "CVE-2017-14116",
    "CVE-2017-14117"
  );
  script_bugtraq_id(100585);

  script_name(english:"AT&T U-verse Arris Modems NVG589 / NVG599 / 5268AC Multiple Vulnerabilities (SharknATTo)");
  script_summary(english:"Looks for the product and version in the about page.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities, including multiple
remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Arris device's self report model is NVG589, NVG599 or 5268AC.
It is, therefor, affected by multiple vulnerabilities, including a firewall
bypass, multiple instances of hardcoded credentials, privilege escalation, and
remote code execution.

Note: Nessus has not checked the firmware version and is detecting this vulnerability
based on the device's self reported model number.");
  script_set_attribute(attribute:"see_also", value:"https://www.nomotion.net/blog/sharknatto/");
  script_set_attribute(attribute:"solution", value:
"No vendor-supplied fix is currently available. Contact vendor for further details.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14116");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port     = get_http_port(default:80);
item = "/xslt?PAGE=C_0_0";
vuln = FALSE;

res = http_send_recv3(method:"GET", item:item, port:port);
if (!isnull(res[2])  && '<a href="/xslt?PAGE=C_2_0">LAN</a>' >< res[2] && '<a href="/xslt?PAGE=C_3_0">Firewall</a>' >< res[2])
{
  pat = "<td>(NVG59[89]|5268AC)</td>";
  match = pregmatch(string:res[2], pattern:pat);
  if (!isnull(match))
  {
    model  = match[1];
    vuln = TRUE;
  }
}

if(vuln)
{
  report = '\nBased on its self-reported model number the remote device is vulnerable.\n';
  report += '\n    Model : ' + model;
  report += '\n    Fix   : Contact vendor for further details.\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_HOST_NOT, "an affected model");
