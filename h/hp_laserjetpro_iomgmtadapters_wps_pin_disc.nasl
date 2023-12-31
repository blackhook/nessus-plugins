#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(69282);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-4807");
  script_bugtraq_id(61565);
  script_xref(name:"IAVB", value:"2013-B-0080");

  script_name(english:"HP LaserJet Pro /IoMgmt/Adapters/wifi0/WPS/Pin WPS PIN Disclosure");
  script_summary(english:"Attempts to obtain WPS PIN");

  script_set_attribute(attribute:"synopsis", value:
"The remote printer is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote HP LaserJet Pro printer is affected by an information
disclosure vulnerability.  The file '/IoMgmt/Adapters/wifi0/WPS/Pin'
contains the 'Wi-Fi Protected Security' (WPS) PIN.  This information can
be used by an attacker in further attacks.");
  # https://sekurak.pl/hp-laserjet-pro-printers-remote-admin-password-extraction/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6839c51c");
  # http://h20566.www2.hp.com/portal/site/hpsc/template.PAGE/public/kb/docDisplay/?docId=emr_na-c03825817-2&ac.admitted=1375460537894.876444892.199480143
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08935147");
  script_set_attribute(attribute:"solution", value:
"Update the printer's firmware or disable file system access via the
Postscript interface.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4807");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:laserjet");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_laserjet_detect.nasl");
  script_require_keys("www/hp_laserjet/pname");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, dont_break:TRUE, embedded:TRUE);

url = '/IoMgmt/Adapters/wifi0/WPS/Pin';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
pwd_str = "";

if (
  "THIS DATA SUBJECT TO DISCLAIMER" >!< res[2] &&
  "<io:WpsSession xmlns:io" >!< res[2] &&
  "<wifi:WpsPin>" >!< res[2] &&
  "</wifi:WpsPin>" >!< res[2]
) audit(AUDIT_WEB_APP_NOT_AFFECTED, "HP LaserJet Pro admin interface", build_url(port:port, qs:url));

marker = stridx(res[2], "<wifi:WpsPin>");
if (marker < 0)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "HP LaserJet Pro admin interface", build_url(port:port, qs:url));
pin_txt = res[2] - substr(res[2], 0, marker);

marker = stridx(pin_txt, "</wifi:WpsPin>");
if (marker < 0)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "HP LaserJet Pro admin interface", build_url(port:port, qs:url));

pin_txt = pin_txt - substr(pin_txt, marker);
pin_txt = pin_txt - "wifi:WpsPin>";

len = strlen(pin_txt);
if (len < 1)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "HP LaserJet Pro admin interface", build_url(port:port, qs:url));

# Mask PIN
if (len > 4)
  clean_pin = substr(pin_txt,0,1) + crap(data:"*", len - 4) + substr(pin_txt, len - 2);
else
  clean_pin = substr(pin_txt,0,0) + "**" + substr(pin_txt, len - 1);

if (report_verbosity > 0)
{
  report =
    '\n' +
    '\nNessus was able to verify the issue and obtain the administrative password : ' +
    '\n\n' +
    '\n  URL     : ' + build_url(port:port, qs:url) +
    '\n  WPS PIN : ' + clean_pin +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
