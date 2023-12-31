#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58540);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/18");

  script_cve_id("CVE-2012-0772", "CVE-2012-0773", "CVE-2012-6270");
  script_bugtraq_id(52748);

  script_name(english:"Flash Player for Mac <= 10.3.183.16 / 11.1.102.63 Multiple Memory Corruption Vulnerabilities (APSB12-07)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host has a browser plugin that is affected by
multiple memory corruption vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the instance of Flash Player installed on
the remote Mac OS X host is 10.x equal to or earlier than
10.3.183.16 or 11.x equal to or earlier than 11.1.102.63.  It is,
therefore, reportedly affected by several critical memory corruption 
vulnerabilities :

  - Memory corruption vulnerabilities related to URL 
    security domain checking. (CVE-2012-0772)

  - A flaw in the NetStream Class that could lead to remote
    code execution. (CVE-2012-0773)

By tricking a victim into visiting a specially crafted page, an
attacker may be able to utilize these vulnerabilities to execute
arbitrary code subject to the users' privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-057/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/522413/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-07.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Flash version 11.2.202.228 / 10.3.183.18 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0772");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2021 Tenable Network Security, Inc.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");

# nb: we're checking for versions less than *or equal to* the cutoff!
tenx_cutoff_version    = "10.3.183.16";
tenx_fixed_version     = "10.3.183.18";
elevenx_cutoff_version = "11.1.102.63";
elevenx_fixed_version  = "11.2.202.228";
fixed_version_for_report = NULL;

# 10x
if (ver_compare(ver:version, fix:tenx_cutoff_version, strict:FALSE) <= 0)
  fixed_version_for_report = tenx_fixed_version;

# 11x
if (
  version =~ "^11\." &&
  ver_compare(ver:version, fix:elevenx_cutoff_version, strict:FALSE) <= 0
) fixed_version_for_report = elevenx_fixed_version;

if (!isnull(fixed_version_for_report))
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : '+fixed_version_for_report+'\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else exit(0, "The Flash Player for Mac "+version+" install is not affected.");
