#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101298);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-6669");
  script_bugtraq_id(99196);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc47758");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc51227");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc51242");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170621-wnrp");

  script_name(english:"Cisco WebEx Network Recording Player ARF File RCE (cisco-sa-20170621-wnrp)");
  script_summary(english:"Checks WebEx file version numbers.");

  script_set_attribute(attribute:"synopsis", value:
"The video player installed on the remote Windows host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco WebEx Network Recording Player installed on the
remote host is affected by a remote code execution vulnerability due
to multiple buffer overflow conditions in the Advanced Recording
Format (ARF) file player. An unauthenticated, remote attacker can
exploit this, by convincing a user to open a specially crafted ARF
file using email or a URL, to cause a denial of service condition or
the execution of arbitrary code.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170621-wnrp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43983fb7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version of WebEx Network Recording
Player referenced in Cisco advisory cisco-sa-20170621-wnrp.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6669");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_advanced_recording_format_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("webex_player_installed.nasl");
  script_require_keys("SMB/ARF Player/path");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

path = get_kb_item_or_exit('SMB/ARF Player/path');
app =  'Cisco WebEx Network Recording Player';
get_kb_item_or_exit("SMB/Registry/Enumerated");
ver = NULL;

# Connect to the appropriate share.
port = kb_smb_transport();
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();

if (!smb_session_init())
  audit(AUDIT_FN_FAIL, "smb_session_init");

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
file_path = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file               : file_path + "buildver.ini",
  desired_access     : GENERIC_READ,
  file_attributes    : FILE_ATTRIBUTE_NORMAL,
  share_mode         : FILE_SHARE_READ,
  create_disposition : OPEN_EXISTING
);

if (!isnull(fh))
{
  size = GetFileSize(handle:fh);
  if (size > 0)
  {
    blob = ReadFile(handle:fh, length:size, offset:0);
    ver = pregmatch(
      pattern : "ClientBuildVersionNumber=([0-9\.]+)",
      icase   : TRUE,
      string  : blob
    );
    if (!empty_or_null(ver))
      ver = ver[1];
    else
    {
      CloseFile(handle:fh);
      NetUseDel();
      audit(AUDIT_VER_FAIL, path + "buildver.ini");
    }
  }
  CloseFile(handle:fh);
}
NetUseDel();

if (empty_or_null(ver))
  audit(AUDIT_UNKNOWN_APP_VER, app);

if (ver =~ "^29\.")
{
  fix = "29.13.130.0";
  min = "29.0.0.0";
}
else if (ver =~ "^30\.")
{
  fix = "30.17.0.0";
  min = "30.0.0.0";
}
else if (ver =~ "^31\.")
{
  fix = "31.10.0.0";
  min = "31.0.0.0";
}
else audit(AUDIT_INST_VER_NOT_VULN, app, ver);

if (ver_compare(ver:ver, fix:fix, minver:min, strict:FALSE) <0)
{
  report = report_items_str(
    report_items:make_array(
      "Path", path,
      "Installed version", ver,
      "Fixed version", fix
    ),
    ordered_fields:make_list("Path", "Installed version", "Fixed version")
  );
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, ver);
