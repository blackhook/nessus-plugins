#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110397);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2018-4945",
    "CVE-2018-5000",
    "CVE-2018-5001",
    "CVE-2018-5002"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"Adobe Flash Player <= 29.0.0.171 (APSB18-19)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Windows
host is equal or prior to version 29.0.0.171. It is therefore 
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb18-19.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 30.0.0.113 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5002");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("flash_player_installed.nasl");
  script_require_keys("SMB/Flash_Player/installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Flash_Player/installed");

# Identify vulnerable versions.
info = "";
variants = make_list(
  "Plugin",
  "ActiveX",
  "Chrome",
  "Chrome_Pepper"
);

# we're checking for versions less than *or equal to* the cutoff!
foreach variant (variants)
{
  vers = get_kb_list("SMB/Flash_Player/"+variant+"/Version/*");
  files = get_kb_list("SMB/Flash_Player/"+variant+"/File/*");

  if (isnull(vers) || isnull(files))
    continue;

  foreach key (keys(vers))
  {
    ver = vers[key];
    if (isnull(ver))
      continue;

    # <= 29.0.0.171
    if (ver_compare(ver:ver,fix:"29.0.0.171",strict:FALSE) <= 0)
    {
      num = key - ("SMB/Flash_Player/"+variant+"/Version/");
      file = files["SMB/Flash_Player/"+variant+"/File/"+num];
      if (variant == "Plugin")
      {
        info += '\n  Product           : Browser Plugin (for Firefox / Netscape / Opera)';
        fix = "30.0.0.113";
      }
      else if (variant == "ActiveX")
      {
        info += '\n  Product           : ActiveX control (for Internet Explorer)';
        fix = "30.0.0.113";
      }
      else if ("Chrome" >< variant)
      {
        info += '\n  Product           : Browser Plugin (for Google Chrome)';
        if (variant == "Chrome")
          fix = "Upgrade to a version of Google Chrome running Flash Player 30.0.0.113";
      }
      info += '\n  Path              : ' + file +
              '\n  Installed version : ' + ver;
      if (variant == "Chrome_Pepper")
        info += '\n  Fixed version     : 30.0.0.113 (Chrome PepperFlash)';
      else if (!isnull(fix))
        info += '\n  Fixed version     : '+fix;
      info += '\n';
    }
  }
}

if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:info);
}
else
{
  if (thorough_tests)
    exit(0, 'No vulnerable versions of Adobe Flash Player were found.');
  else
    exit(1, 'Google Chrome\'s built-in Flash Player may not have been detected because the \'Perform thorough tests\' setting was not enabled.');
}
