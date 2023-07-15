#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(31096);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2007-6148", "CVE-2007-6149", "CVE-2007-6431");
  script_bugtraq_id(27762);
  script_xref(name:"SECUNIA", value:"28946");

  script_name(english:"Adobe Flash Media Server < 2.0.5 Multiple Remote Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Flash media server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Adobe's Flash Media Server, an application
server for Flash-based applications. 

The Edge server component included with the version of Flash Media
Server installed on the remote host contains several integer overflow
and memory corruption errors that can be triggered when parsing
specially crafted Real Time Message Protocol (RTMP) packets.  An
unauthenticated, remote attacker can leverage these issues to crash the
affected service or execute arbitrary code with SYSTEM-level
privileges (under Windows), potentially resulting in a complete
compromise of the affected host.");
  # https://labs.idefense.com/verisign/intelligence/2009/vulnerabilities/display.php?id=662
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1769e068");
  # https://labs.idefense.com/verisign/intelligence/2009/vulnerabilities/display.php?id=663
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?401cb634");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2008/Feb/174");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2008/Feb/178");
  script_set_attribute(attribute:"see_also", value:"https://www.adobe.com/support/security/bulletins/apsb08-03.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Flash Media Server 2.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_media_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2008-2022 Tenable Network Security, Inc.");

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

if (ver_compare(ver:version, fix:"2.0.5") == -1)
{
  if (report_verbosity)
  {
    report = 
      '\n' +
      'Version source : ' + source +
      '\n' +
      'Installed version : ' + version +
      '\n' +
      'Fixed version : 2.0.5\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The Adobe Flash Media Server version "+version+" on port "+port+" is not affected.");
