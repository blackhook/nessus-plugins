##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141492);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/22");

  script_cve_id("CVE-2020-9746");
  script_xref(name:"IAVA", value:"2020-A-0464");

  script_name(english:"Adobe Flash Player for Mac <= 32.0.0.433 (APSB20-58)");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS or Mac OSX host has a browser plugin installed that is affected by arbitrary code execution
vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote macOS or Mac OS X host is equal or prior to version
32.0.0.433. It is therefore affected by a NULL pointer dereference flaw. An unauthenticated, remote attacker can exploit
this, by inserting malicious strings in an HTTP response, to execute arbitrary code in the context of the current user.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb20-58.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 32.0.0.445 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9746");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}

version = get_kb_item_or_exit('MacOSX/Flash_Player/Version');
path = get_kb_item_or_exit('MacOSX/Flash_Player/Path');

cutoff_version = '32.0.0.433';
fix = '32.0.0.445';
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
else audit(AUDIT_INST_PATH_NOT_VULN, 'Flash Player for Mac', version, path);
