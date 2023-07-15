#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90425);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2016-1006",
    "CVE-2016-1011",
    "CVE-2016-1012",
    "CVE-2016-1013",
    "CVE-2016-1014",
    "CVE-2016-1015",
    "CVE-2016-1016",
    "CVE-2016-1017",
    "CVE-2016-1018",
    "CVE-2016-1019",
    "CVE-2016-1020",
    "CVE-2016-1021",
    "CVE-2016-1022",
    "CVE-2016-1023",
    "CVE-2016-1024",
    "CVE-2016-1025",
    "CVE-2016-1026",
    "CVE-2016-1027",
    "CVE-2016-1028",
    "CVE-2016-1029",
    "CVE-2016-1030",
    "CVE-2016-1031",
    "CVE-2016-1032",
    "CVE-2016-1033"
  );
  script_bugtraq_id(
    85856,
    85926,
    85927,
    85928,
    85930,
    85931,
    85932,
    85933
  );
  script_xref(name:"ZDI", value:"ZDI-16-225");
  script_xref(name:"ZDI", value:"ZDI-16-226");
  script_xref(name:"ZDI", value:"ZDI-16-227");
  script_xref(name:"ZDI", value:"ZDI-16-228");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Adobe Flash Player <= 21.0.0.197 Multiple Vulnerabilities (APSB16-10)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Windows host
is prior or equal to version 21.0.0.197. It is, therefore, affected by
multiple vulnerabilities :

  - An Address Space Layout Randomization (ASLR) bypass
    vulnerability exists that allows an attacker to predict
    memory offsets in the call stack. (CVE-2016-1006)

  - Multiple use-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2016-1011,
    CVE-2016-1013, CVE-2016-1016, CVE-2016-1017,
    CVE-2016-1031)

  - Multiple memory corruption issues exist that allow an
    attacker to execute arbitrary code. (CVE-2016-1012,
    CVE-2016-1020, CVE-2016-1021, CVE-2016-1022,
    CVE-2016-1023, CVE-2016-1024, CVE-2016-1025,
    CVE-2016-1026, CVE-2016-1027, CVE-2016-1028,
    CVE-2016-1029, CVE-2016-1032, CVE-2016-1033)

  - A directory search path vulnerability exists that allows
    an attacker to disclose sensitive resources.
    (CVE-2016-1014)

  - Multiple type confusion errors exist that allow an
    attacker to execute arbitrary code. (CVE-2016-1015,
    CVE-2016-1019)

  - An overflow condition exists that is triggered when
    handling JPEG-XR compressed image content. An attacker
    can exploit this to execute arbitrary code.
    (CVE-2016-1018)

  - An unspecified security bypass vulnerability exists.
    (CVE-2016-1030)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-10.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 21.0.0.213 or later.

Alternatively, Adobe has made version 18.0.0.343 available for those
installations that cannot be upgraded to the latest version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1019");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

  if(isnull(vers) || isnull(files))
    continue;

  foreach key (keys(vers))
  {
    ver = vers[key];
    if(isnull(ver))
      continue;

    vuln = FALSE;

    # Chrome Flash <=   21.0.0.197
    if(variant == "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"21.0.0.197",strict:FALSE) <= 0
    ) vuln = TRUE;

    # <= 18.0.0.333
    if(variant != "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"18.0.0.333",strict:FALSE) <= 0
    ) vuln = TRUE;

    # 19 <= 21.0.0.197
    else if(variant != "Chrome_Pepper" && ver =~ "^(?:19|[2-9]\d)\.")
    {
      if (variant == "ActiveX" && ver_compare(ver:ver,fix:"21.0.0.197",strict:FALSE) <= 0)
        vuln = TRUE;
      else if (ver_compare(ver:ver,fix:"21.0.0.197",strict:FALSE) <= 0)
        vuln = TRUE;
    }

    if(vuln)
    {
      num = key - ("SMB/Flash_Player/"+variant+"/Version/");
      file = files["SMB/Flash_Player/"+variant+"/File/"+num];
      if (variant == "Plugin")
      {
        info += '\n  Product           : Browser Plugin (for Firefox / Netscape / Opera)';
        fix = "21.0.0.213 / 18.0.0.343";
      }
      else if (variant == "ActiveX")
      {
        info += '\n  Product           : ActiveX control (for Internet Explorer)';
        fix = "21.0.0.213 / 18.0.0.343";
      }
      else if ("Chrome" >< variant)
      {
        info += '\n  Product           : Browser Plugin (for Google Chrome)';
        if(variant == "Chrome")
          fix = "Upgrade to a version of Google Chrome running Flash Player 21.0.0.213";
      }
      info += '\n  Path              : ' + file +
              '\n  Installed version : ' + ver;
      if (variant == "Chrome_Pepper")
        info += '\n  Fixed version     : 21.0.0.213 (Chrome PepperFlash)';
      else if(!isnull(fix))
        info += '\n  Fixed version     : '+fix;
      info += '\n';
    }
  }
}

if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  security_report_v4(port:port, extra:info, severity:SECURITY_HOLE);
}
else
{
  if (thorough_tests)
    exit(0, 'No vulnerable versions of Adobe Flash Player were found.');
  else
    exit(1, 'Google Chrome\'s built-in Flash Player may not have been detected because the \'Perform thorough tests\' setting was not enabled.');
}
