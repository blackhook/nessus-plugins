#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119424);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/22");

  script_cve_id("CVE-2018-15982", "CVE-2018-15983");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/15");

  script_name(english:"Adobe Flash Player for Mac <= 31.0.0.153 (APSB18-42)");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS or Mac OSX host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote macOS or Mac
OS X host is equal or prior to version 31.0.0.153.
It is therefore affected by the following vulnerabilities :

  - An unspecified use-after-free error exists that allows
    remote code execution. (CVE-2018-15982)

  - An unspecified insecure library loading error exists
    that allows privilege escalation. (CVE-2018-15983)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb18-42.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 32.0.0.101 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15982");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");
path = get_kb_item_or_exit("MacOSX/Flash_Player/Path");

cutoff_version = "31.0.0.153";
fix = "32.0.0.101";
# We're checking for versions less than or equal to the cutoff!
if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Flash Player for Mac", version, path);
