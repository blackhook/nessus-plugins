#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91165);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2016-1096",
    "CVE-2016-1097",
    "CVE-2016-1098",
    "CVE-2016-1099",
    "CVE-2016-1100",
    "CVE-2016-1101",
    "CVE-2016-1102",
    "CVE-2016-1103",
    "CVE-2016-1104",
    "CVE-2016-1105",
    "CVE-2016-1106",
    "CVE-2016-1107",
    "CVE-2016-1108",
    "CVE-2016-1109",
    "CVE-2016-1110",
    "CVE-2016-4108",
    "CVE-2016-4109",
    "CVE-2016-4110",
    "CVE-2016-4111",
    "CVE-2016-4112",
    "CVE-2016-4113",
    "CVE-2016-4114",
    "CVE-2016-4115",
    "CVE-2016-4116",
    "CVE-2016-4117",
    "CVE-2016-4120",
    "CVE-2016-4121",
    "CVE-2016-4160",
    "CVE-2016-4161",
    "CVE-2016-4162",
    "CVE-2016-4163"
  );
  script_bugtraq_id(90505);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Adobe Flash Player for Mac <= 21.0.0.226 Multiple Vulnerabilities (APSB16-15)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Mac OS X
host is equal or prior to 21.0.0.226. It is, therefore, affected by
multiple vulnerabilities :

  - Multiple type confusion errors exist that allow an
    attacker to execute arbitrary code. (CVE-2016-1105,
    CVE-2016-4117)

  - Multiple use-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2016-1097,
    CVE-2016-1106, CVE-2016-1107, CVE-2016-1108,
    CVE-2016-1109, CVE-2016-1110, CVE-2016-4108,
    CVE-2016-4110, CVE-2016-4121)

  - A heap buffer overflow condition exists that allows an
    attacker to execute arbitrary code. (CVE-2016-1101)

  - An unspecified buffer overflow exists that allows an
    attacker to execute arbitrary code. (CVE-2016-1103)

  - Multiple memory corruption issues exist that allow an
    attacker to execute arbitrary code. (CVE-2016-1096,
    CVE-2016-1098, CVE-2016-1099, CVE-2016-1100,
    CVE-2016-1102, CVE-2016-1104, CVE-2016-4109,
    CVE-2016-4111, CVE-2016-4112, CVE-2016-4113,
    CVE-2016-4114, CVE-2016-4115, CVE-2016-4120,
    CVE-2016-4160, CVE-2016-4161, CVE-2016-4162,
    CVE-2016-4163)

  - A flaw exists when loading dynamic-link libraries. An
    attacker can exploit this, via a specially crafted .dll
    file, to execute arbitrary code. (CVE-2016-4116)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-15.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 21.0.0.242 or later.

Alternatively, Adobe has made version 18.0.0.352 available for those installs
that cannot be upgraded to the latest version");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4117");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-4163");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player DeleteRangeTimelineOperation Type-Confusion');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");
path = get_kb_item_or_exit("MacOSX/Flash_Player/Path");

if (ver_compare(ver:version, fix:"19.0.0.0", strict:FALSE) >= 0)
{
  cutoff_version = "21.0.0.226";
  fix = "21.0.0.242";
}
else
{
  cutoff_version = "18.0.0.343";
  fix = "18.0.0.352";
}

# we're checking for versions less than or equal to the cutoff!
if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Flash Player for Mac", version, path);
