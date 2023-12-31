#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(100388);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/30");

  script_cve_id("CVE-2017-7494");
  script_bugtraq_id(98636);
  script_xref(name:"EDB-ID", value:"42060");
  script_xref(name:"EDB-ID", value:"42084");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");

  script_name(english:"Samba 3.5.x < 4.4 / 4.4.x < 4.4.14 / 4.5.x < 4.5.10 / 4.6.x < 4.6.4 Shared Library RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is 3.5.x prior to
4.4.x, or it is 4.4.x prior to 4.4.14, 4.5.x prior to 4.5.10, or 4.6.x
prior to 4.6.4. It is, therefore, affected by an unspecified remote
code execution vulnerability. An authenticated, remote attacker can
exploit this, via a specially crafted shared library uploaded to a
writable share, to cause the server to load and execute arbitrary code
with root privileges.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2017-7494.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/samba-4.4.14.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/samba-4.5.10.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/samba-4.6.4.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.4.14 / 4.5.10 / 4.6.4 or later.

Alternatively, add the parameter 'nt pipe support = no' to the
[global] section of the smb.conf and restart smbd. This prevents
clients from accessing any named pipe endpoints. Note that this
workaround can disable some expected functionality for Windows
clients.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7494");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba is_known_pipename() Arbitrary Module Load');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
# 3.5.x < 4.x
if (version =~ "^4\.6\.")
  fix = '4.6.4';
else if (version =~ "^4\.5\.")
  fix = '4.5.10';
else
  fix = '4.4.14';

if ( !isnull(fix) &&
     (ver_compare(ver:version, fix:fix, regexes:regexes) < 0) &&
     (ver_compare(ver:version, fix:'3.5.0', regexes:regexes) >= 0) )
{
  if (version =~ "^3\.[56]($|[^0-9])" || version =~ "^4\.[123]($|[^0-9])")
    fix = 'Upgrade to a supported version (e.g. 4.6.4/4.5.10/4.4.14)';

  report = '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fix +
           '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);
