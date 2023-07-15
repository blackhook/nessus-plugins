#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111974);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id(
    "CVE-2018-1139",
    "CVE-2018-1140",
    "CVE-2018-10858",
    "CVE-2018-10918",
    "CVE-2018-10919"
  );
  script_bugtraq_id(
    105081,
    105082,
    105083,
    105084,
    105085
  );

  script_name(english:"4.6.x < 4.6.16 / 4.7.x < 4.7.9 / 4.8.x < 4.8.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Samba.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is 4.6.x prior to 
4.6.16, or 4.7.x prior to 4.7.9, or 4.8.x prior to 4.8.4. It is,
therefore, affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2018-1139.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2018-1140.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2018-10919.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2018-10918.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2018-10858.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.6.16 / 4.7.9 / 4.8.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10858");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (version =~ "^4(\.[0-8])?$")
  audit(AUDIT_VER_NOT_GRANULAR, "Samba", port, version);

fix = NULL;

regexes = make_array(-2, "a(\d+)", -1, "rc(\d+)");

# Affected :
# Note versions prior to 4.4 are EoL
# 4.6.x < 4.6.16
# 4.7.x < 4.7.9
# 4.8.x < 4.8.4
if (version =~ "^4\.6\.")
  fix = '4.6.16';
else if (version =~ "^4\.7\.")
  fix = '4.7.9';
else if (version =~ "^4\.8\.")
  fix = '4.8.4';

if ( !isnull(fix) &&
     (ver_compare(ver:version, fix:fix, regexes:regexes) < 0) &&
     (ver_compare(ver:version, fix:'4.0.0', regexes:regexes) >= 0) )
{
  report = '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fix +
           '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);
