#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64584);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2013-0637",
    "CVE-2013-0638",
    "CVE-2013-0639",
    "CVE-2013-0642",
    "CVE-2013-0644",
    "CVE-2013-0645",
    "CVE-2013-0647",
    "CVE-2013-0649",
    "CVE-2013-1365",
    "CVE-2013-1366",
    "CVE-2013-1367",
    "CVE-2013-1368",
    "CVE-2013-1369",
    "CVE-2013-1370",
    "CVE-2013-1372",
    "CVE-2013-1373",
    "CVE-2013-1374"
  );
  script_bugtraq_id(
    57912,
    57916,
    57917,
    57918,
    57919,
    57920,
    57921,
    57922,
    57923,
    57924,
    57925,
    57926,
    57927,
    57929,
    57930,
    57932,
    57933
  );

  script_name(english:"Flash Player <= 10.3.183.51 / 11.5.502.149 Multiple Vulnerabilities (APSB13-05)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of Flash Player installed on the
remote Windows host is 11.x equal or prior to 11.5.502.149, or 10.x
equal or prior to 10.3.183.51.  It is, therefore, potentially affected
by the following vulnerabilities :

  - Several unspecified issues exist that could lead to
    buffer overflows and arbitrary code execution.
    (CVE-2013-1372, CVE-2013-0645, CVE-2013-1373,
    CVE-2013-1369, CVE-2013-1370, CVE-2013-1366,
    CVE-2013-1365, CVE-2013-1368, CVE-2013-0642,
    CVE-2013-1367)

  - Several unspecified use-after-free vulnerabilities exist
    that could lead to remote code execution. (CVE-2013-0649,
    CVE-2013-1374, CVE-2013-0644)

  - Two unspecified issues exist that could lead to memory
    corruption and arbitrary code execution. (CVE-2013-0638,
    CVE-2013-0647)

  - An unspecified information disclosure vulnerability
    exists. (CVE-2013-0637)

  - An unspecified integer overflow vulnerability exists.
    (CVE-2013-0639)");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-05.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 10.3.183.63 / 11.6.602.168 or
later, or Google Chrome PepperFlash 11.6.602.167 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1374");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("flash_player_installed.nasl");
  script_require_keys("SMB/Flash_Player/installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Flash_Player/installed");

# Identify vulnerable versions.
info = "";

# we're checking for versions less than *or equal to* the cutoff!
foreach variant (make_list("Plugin", "ActiveX", "Chrome", "Chrome_Pepper"))
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
          (
            # Chrome Flash <= 11.5.31.139
            variant == "Chrome_Pepper" &&
            (
              iver[0] == 11 &&
              (
                iver[1] < 5 ||
                (
                  iver[1] == 5 &&
                  (
                    iver[2] < 31 ||
                    (iver[2] == 31 && iver[3] <= 139)
                  )
                )
              )
            )
          ) ||
          (
            variant != "Chrome_Pepper" &&
            (
              # 10.x <= 10.3.183.51
              (
                iver[0] == 10 &&
                (
                  iver[1] < 3 ||
                  (
                    iver[1] == 3 &&
                    (
                      iver[2] < 183 ||
                      (iver[2] == 183 && iver[3] <= 51)
                    )
                  )
                )
              )
              ||
              # 11.x <= 11.5.502.149
              (
                iver[0] == 11 &&
                (
                  iver[1] < 5 ||
                  (
                    iver[1] == 5 &&
                    (
                      iver[2] < 502 ||
                      (iver[2] == 502 && iver[3] <= 149)
                    )
                  )
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
          else if ("Chrome" >< variant)
          {
            info += '\n Product : Browser Plugin (for Google Chrome)';
          }
          info += '\n  Path              : ' + file +
                  '\n  Installed version : ' + ver;
          if (variant == "Chrome_Pepper")
            info += '\n  Fixed version     : 11.6.602.167 (Chrome PepperFlash)';
          else
            info += '\n  Fixed version     : 10.3.183.63 / 11.6.602.168';
          info += '\n';
        }
      }
    }
  }
}

if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0) security_hole(port:port, extra:info);
  else security_hole(port);
}
else
{
  if (thorough_tests)
    exit(0, 'No vulnerable versions of Adobe Flash Player were found.');
  else
    exit(1, 'Google Chrome\'s built-in Flash Player may not have been detected because the \'Perform thorough tests\' setting was not enabled.');
}
