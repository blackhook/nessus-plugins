#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(38700);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2009-1365");
  script_bugtraq_id(34790);
  script_xref(name:"SECUNIA", value:"34878");

  script_name(english:"Adobe Flash Media Server RPC Privilege Escalation (APSB09-05)");

  script_set_attribute(attribute:"synopsis", value:
"The remote media server has a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Adobe Flash Media Server, an application
server for Flash-based applications.

The version running on the remote host has an unspecified RPC
vulnerability. This can reportedly be exploited to execute remote
procedures within an server-side ActionScript file running on the
server.");
  script_set_attribute(attribute:"see_also", value:"https://www.adobe.com/support/security/bulletins/apsb09-05.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Flash Media Server 3.5.2 / 3.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_media_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2022 Tenable Network Security, Inc.");

  script_dependencies("adobe_fms_detect.nasl");
  script_require_keys("rtmp/adobe_fms");
  script_require_ports("Services/rtmp", 1935, 19350);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_kb_item_or_exit("Services/rtmp");
version = get_kb_item_or_exit("rtmp/" + port + "/adobe_fms/version");
source = get_kb_item_or_exit("rtmp/" + port + "/adobe_fms/version_source");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 3 ||
  (ver[0] == 3 && ver[1] == 0 && ver[2] < 4) ||
  (ver[0] == 3 && ver[1] > 0 && (ver[1] < 5 || (ver[1] == 5 && ver[2] < 2)))
)
{
  if (report_verbosity)
  {
    report = 
      '\n' +
      'Version source : ' + source +
      '\n' +
      'Installed version : ' + version +
      '\n' +
      'Fixed version : 3.0.4 / 3.5.2\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The Adobe Flash Media Server version "+version+" on port "+port+" is not affected.");
