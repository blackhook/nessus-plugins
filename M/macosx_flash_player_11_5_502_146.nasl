#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63452);
  script_version("1.8");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id("CVE-2013-0630");
  script_bugtraq_id(57184);

  script_name(english:"Flash Player for Mac <= 10.3.183.48 / 11.5.502.136 Buffer Overflow (APSB13-01)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin that is affected by a
buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of Flash Player installed on the
remote Mac OS X host is 11.x equal to or earlier than 11.5.502.136, or
10.x equal to or earlier than 10.3.183.48.  It is, therefore,
potentially affected by an unspecified buffer overflow vulnerability.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-01.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 10.3.183.50 / 11.5.502.146 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0630");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");
path = get_kb_item_or_exit("MacOSX/Flash_Player/Path");

# nb: we're checking for versions less than *or equal to* the cutoff!
tenx_cutoff_version = "10.3.183.48";
tenx_fixed_version = "10.3.183.50";
elevenx_cutoff_version = "11.5.502.136";
elevenx_fixed_version = "11.5.502.146";
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
      '\n  Path              : ' + path + 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : ' +fixed_version_for_report + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Flash Player for Mac", version, path);
