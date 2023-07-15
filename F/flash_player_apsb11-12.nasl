#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(54299);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2011-0579",
    "CVE-2011-0618",
    "CVE-2011-0619",
    "CVE-2011-0620",
    "CVE-2011-0621",
    "CVE-2011-0622",
    "CVE-2011-0623",
    "CVE-2011-0624",
    "CVE-2011-0625",
    "CVE-2011-0626",
    "CVE-2011-0627",
    "CVE-2011-0628"
  );
  script_bugtraq_id(
    47806,
    47807,
    47808,
    47809,
    47810,
    47811,
    47812,
    47813,
    47814,
    47815,
    47847,
    47961
  );
  script_xref(name:"SECUNIA", value:"44590");

  script_name(english:"Flash Player < 10.3.181.14 Multiple Vulnerabilities (APSB11-12)");

  script_set_attribute(attribute:"synopsis", value:
"A browser plugin is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Several critical vulnerabilities exist in versions of Flash Player
earlier than 10.3.181.14 :

  - An unspecified information disclosure vulnerability
    exists. (CVE-2011-0579)

  - An unspecified integer overflow vulnerability exists.
    (CVE-2011-0618, CVE-2011-0628)

  - Unspecified memory corruption vulnerabilities exist.
    (CVE-2011-0619, CVE-2011-0620, CVE-2011-0621, 
    CVE-2011-0622, CVE-2011-0627)

  - Unspecified boundary-checking errors exist.
    (CVE-2011-0623, CVE-2011-0624, CVE-2011-0625,
    CVE-2011-0626)");
  # https://labs.idefense.com/verisign/intelligence/2009/vulnerabilities/display.php?id=902
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f9d009b");
  # https://labs.idefense.com/verisign/intelligence/2009/vulnerabilities/display.php?id=903
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?185a7880");
  # https://labs.idefense.com/verisign/intelligence/2009/vulnerabilities/display.php?id=908
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03a97fa4");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-12.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash version 10.3.181.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2022 Tenable Network Security, Inc.");

  script_dependencies("flash_player_installed.nasl");
  script_require_keys("SMB/Flash_Player/installed");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

get_kb_item_or_exit('SMB/Flash_Player/installed');

# Identify vulnerable versions.
info = '';

foreach variant (make_list("Plugin", "ActiveX", "Chrome"))
{
  vers = get_kb_list("SMB/Flash_Player/"+variant+"/Version/*");
  files = get_kb_list("SMB/Flash_Player/"+variant+"/File/*");
  if (!isnull(vers) && !isnull(files))
  {
    foreach key (keys(vers))
    {
      ver = vers[key];

      if (ver)
      {
        iver = split(ver, sep:'.', keep:FALSE);
        for (i=0; i<max_index(iver); i++)
          iver[i] = int(iver[i]);

        if (
          iver[0] < 10 ||
          (
            iver[0] == 10 &&
            (
              iver[1] < 3 ||
              (
                iver[1] == 3 &&
                (
                  iver[2] < 181 ||
                  (iver[2] == 181 && iver[3] < 14)
                )
              )
            )
          )
        )
        {
          num = key - ("SMB/Flash_Player/"+variant+"/Version/");
          file = files["SMB/Flash_Player/"+variant+"/File/"+num];
          if (variant == "Plugin")
          {
            info += '\n  Product: Browser Plugin (for Firefox / Netscape / Opera)';
          }
          else if (variant == "ActiveX")
          {
            info += '\n Product : ActiveX control (for Internet Explorer)';
          }
          else if (variant == "Chrome")
          {
            info += '\n Product : Browser Plugin (for Google Chrome)';
          }
          info += '\n  Path              : ' + file +
                  '\n  Installed version : ' + ver  +
                  '\n  Fixed version     : 10.3.181.14';

          if (variant == "Chrome")
            info += ' (as included with Google Chrome 11.0.696.68)';

          info += '\n';
        }
      }
    }
  } 
}

if (info)
{
  if (report_verbosity > 0)
    security_hole(port:get_kb_item("SMB/transport"), extra:info);
  else
    security_hole(get_kb_item("SMB/transport"));
}
else exit(0, 'The host is not affected.');
