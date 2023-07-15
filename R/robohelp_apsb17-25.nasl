#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103221);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2017-3104", "CVE-2017-3105");
  script_bugtraq_id(100707, 100709);
  script_xref(name:"IAVB", value:"2017-B-0122-S");

  script_name(english:"Adobe RoboHelp Multiple Vulnerabilities (APSB17-25)");
  script_summary(english:"Checks for APSB17-25 patches");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe RoboHelp installed on the remote Windows host is
affected by multiple vulnerabilities, including a cross-site scripting
(XSS) vulnerability as well as an unvalidated URL redirect
vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/robohelp/apsb17-25.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate fix according to the instructions in Adobe
Security Bulletin APSB17-25.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3105");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:robohelp");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("robohelp_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe RoboHelp");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

# Used for reporting
global_var port = kb_smb_transport();

function robohelp_check_file(file, path)
{
  local_var patch, nopatch, login, domain, pass, share;
  local_var rc, fh, size, text, vuln, off;

  vuln = FALSE;

  if (file =~ "ehlpdhtm\.js")
  {
    patch = '" + window.getFilePath() +"';
    nopatch = '" + location +"';
  }
  if (file =~ "whphost\.js")
  {
    patch = "gsPath=_getPath(decodeURI(location.href));";
    nopatch = "gsPath=gsPath.substring(0,nPosFile+1);";
  }

  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();

  if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  fh = CreateFile(
      file:file,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );

  if (!isnull(fh))
  {
    size = GetFileSize(handle:fh);
    if (size)
    {
      off = 0;
      while (off < size)
      {
        text = ReadFile(handle:fh, length:10240, offset:off);
        if (strlen(text) == 0) break;

        if ( (patch >!< text) && (nopatch >< text) )
        {
          vuln = TRUE;
          break;
        }
        off += 10240;
      }
    }
    CloseFile(handle:fh);
  }
  NetUseDel();
  return vuln;
}

get_kb_item_or_exit("SMB/Registry/Enumerated");
app = "Adobe RoboHelp";

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];
patched = FALSE;
report = NULL;


# Robohelp 13.x (2017)
if (version =~ "^13\.")
{
  exe_path = hotfix_append_path(path:path, value:"RoboHTML\RoboHTML.exe");
  fver = hotfix_get_fversion(path:exe_path);

  hotfix_handle_error(error_code:fver['error'], file:exe_path, appname:app, exit_on_fail:TRUE);
  hotfix_check_fversion_end();

  ver = join(fver['value'], sep:'.');
  fixed_version = '13.0.0.257';

  if (ver_compare(ver:ver, fix:fixed_version) < 0)
  {
      report +=
       '\n  Installed version : ' + ver +
       '\n  Fixed  version    : ' + fixed_version +
       '\n';
  }
  else
    audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
}

# RoboHelp 12.x (2015)
else if (version =~ "^12\.")
{
  files = make_array();
  files["ehlpdhtm.js"]["path"] = "RoboHTML\";
  files["ehlpdhtm.js"]["patch"] = "ehlpdhtm.zip";

  files["whphost.js"]["path"] = "RoboHTML\WebHelp5Ext\template_stock\";
  files["whphost.js"]['patch'] = "webhelp5ext.zip";

  foreach file (keys(files))
  {
    file_loc = ereg_replace(
      pattern : "^[A-Za-z]:(.*)",
      replace : "\1"+files[file]["path"]+file,
      string  : path
    );

    vuln_install = robohelp_check_file(file : file_loc, path : path);
    if (vuln_install)
    {
      report +=
       '\n  File Checked       : ' + file +
       '\n  Patch Required     : ' + files[file]['patch'] +
       '\n';
    }
  }
}
else if (version =~ "^([0-9]|10|11)\.")
{
  report +=
    '\n  RoboHelp Version     : ' + version +
    '\n  Fix                  : Refer to Adobe support for patch / upgrade instructions'+
    '\n';
}

if (!isnull(report))
{
  if (version =~ "^12\.")
    myreport = '\n  Patch Instructions : https://helpx.adobe.com/robohelp/kb/security-vulnerability-webhelp.html' + report;
  else myreport = report;

  security_report_v4(
    severity : SECURITY_WARNING,
    port     : port,
    extra    : myreport,
    xss      : TRUE
  );
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
