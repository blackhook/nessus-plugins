#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99199);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-2619");
  script_bugtraq_id(97033);

  script_name(english:"Samba 4.4.x < 4.4.12 / 4.5.x < 4.5.7 / 4.6.x < 4.6.1 Path Renaming Symlink Local File Disclosure");
  script_summary(english:"Checks the version of Samba.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is 4.4.x prior to
4.4.12, 4.5.x prior to 4.5.7, or 4.6.x prior to 4.6.1. It is,
therefore, affected by an information disclosure vulnerability due to
a race condition between calls to lstat() for symlink checks and calls
to open() to read a file. A local attacker can exploit this, by
replacing a recently checked path with a symlink, to disclose
arbitrary files on the system.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2017-2619.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/samba-4.4.12.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/samba-4.5.7.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/samba-4.6.1.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.4.12 / 4.5.7 / 4.6.1 or later.
Alternatively, apply the patch or workaround referenced in the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-2619");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

lanman = get_kb_item_or_exit("SMB/NativeLanManager");

if ("Samba " >!< lanman) audit(AUDIT_NOT_LISTEN, "Samba", port);

version = lanman - 'Samba ';

if (version =~ "^4(\.[4-6])?$")
  audit(AUDIT_VER_NOT_GRANULAR, "Samba", port, version);

fix = NULL;

regexes = make_array(-2, "a(\d+)", -1, "rc(\d+)");

# Affected :
# Note versions prior to 4.4 are EoL
# 4.4.x < 4.4.12
# 4.5.x < 4.5.7
# 4.6.x < 4.6.1
if (version =~ "^4\.4\.")
  fix = '4.4.12';
else if (version =~ "^4\.5\.")
  fix = '4.5.7';
else if (version =~ "^4\.6\.")
  fix = '4.6.1';

if (!isnull(fix) && ver_compare(ver:version, fix:fix, regexes:regexes) < 0)
{
  report = '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fix +
           '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);

