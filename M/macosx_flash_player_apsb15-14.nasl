#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(84366);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/22");

  script_cve_id("CVE-2015-3113");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/04");

  script_name(english:"Adobe Flash Player <= 18.0.0.161 RCE (APSB15-14) (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin installed that is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Mac OS X
host is equal or prior to version 18.0.0.161. It is, therefore,
affected by a remote code execution vulnerability due to improper
validation of unspecified user-supplied input. A remote attacker can
exploit this, via specially crafted Flash content, to cause a
heap-based buffer overflow, resulting in the execution of arbitrary
code.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-14.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 18.0.0.194 or later.

Alternatively, Adobe has made version 13.0.0.296 available for those
installations that cannot be upgraded to 18.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3113");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player Nellymoser Audio Decoding Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");
path = get_kb_item_or_exit("MacOSX/Flash_Player/Path");

if (ver_compare(ver:version, fix:"14.0.0.0", strict:FALSE) >= 0)
{
  cutoff_version = "18.0.0.161";
  fix = "18.0.0.194";
}
else
{
  cutoff_version = "13.0.0.292";
  fix = "13.0.0.296";
}

# nb: we're checking for versions less than *or equal to* the cutoff!
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
