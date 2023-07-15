#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(52544);
  script_version("1.786");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"Microsoft Forefront Endpoint Protection / System Center Endpoint Protection / Anti-malware Client Detection and Status");
  script_summary(english:"Checks if Forefront Endpoint Protection, System Center Endpoint Protection, or Anti-malware Client is installed.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus or antimalware application is installed on the remote
host, but it is not working properly.");
  script_set_attribute(attribute:"description", value:
"Microsoft Forefront Endpoint Protection, or another antimalware
product from Microsoft, is installed on the remote host. However,
there is a problem with the installation; either its services are not
running or its engine and/or virus definitions are out of date.");
  # https://web.archive.org/web/20110317014246/http://www.microsoft.com/forefront/endpoint-protection/en/us/default.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a56c4934");
  script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Updates to security software are critical.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:system_center_endpoint_protection");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_enum_services.nasl","smb_hotfixes.nasl","microsoft_windows_defender_win_installed.nbin");  
  script_require_keys("SMB/Registry/Enumerated", "SMB/Services/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include('antivirus.inc');
include('smb_reg_query.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('misc_func.inc');
include('install_func.inc');
include('debug.inc');

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/Services/Enumerated");

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if (!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Find where it's installed.
path = NULL;
avsignatures = NULL;
assignatures = NULL;
engine_version = NULL;

key = "SOFTWARE\Microsoft\Microsoft Antimalware";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallLocation");
  if (!isnull(value)) 
  {
    path = value[1];
    dbg::log(src:SCRIPT_NAME, msg:'Found path via Microsoft Antimalware reg key: '+path);
  }

  RegCloseKey(handle:key_h);
}

# Handle System Center Endpoint Protection / Managed Windows Defender (Windows 10)
scep_ver = NULL;
if(isnull(path) || get_kb_item("SMB/WindowsVersion") == "10")
{
  display_names = get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
  foreach ukey (keys(display_names))
  {
    name = display_names[ukey];
    if (name != 'System Center Endpoint Protection' && name != 'Managed Windows Defender') continue;

    version_key = ukey - 'SMB/Registry/HKLM/' - 'DisplayName' + 'DisplayVersion';
    version_key = str_replace(string:version_key, find:'/', replace:"\");
    scep_ver = get_registry_value(handle:hklm, item:version_key);
    if(isnull(scep_ver)) continue;
    dbg::log(src:SCRIPT_NAME, msg:"Found version via Uninstall reg keys: "+scep_ver);

    install_location_key = ukey - 'SMB/Registry/HKLM/' - 'DisplayName' + 'InstallLocation';
    install_location_key = str_replace(string:install_location_key, find:'/', replace:"\");

    tmp_path = get_registry_value(handle:hklm, item:install_location_key);
    if(isnull(tmp_path)) continue;

    path = tmp_path;
    dbg::log(src:SCRIPT_NAME, msg:"Found path via Uninstall reg keys: "+path);
    # System Center Endpoint Protection uses Windows Defender
    key = "SOFTWARE\Microsoft\Windows Defender";
    break;
  }
}

# Handle Unmanaged Windows Defender
defender_install_count = get_install_count(app_name:'Windows Defender', exit_if_zero:FALSE);

if (defender_install_count > 0)
{
  install = get_single_install(app_name:'Windows Defender', exit_if_unknown_ver:FALSE);
  # Check if disabled - Similar to Plugin ID 103569
  if (!isnull(install['Disabled']))
    exit(0,'Windows Defender is disabled.');
  defender_path = install['path'];
  defender_ver = install['version'];
  defender_engine_version = install['Engine Version'];
  defender_avsignatures = install['Malware Signature Version'];
  dbg::log(src:SCRIPT_NAME, msg:"Found Windows Defender Installation. Version: " + defender_ver);
  if(isnull(path))
  {
    path = defender_path;
    ver = defender_ver;
    engine_version = defender_engine_version;
    dbg::log(src:SCRIPT_NAME, msg:"Found engine_version " + engine_version + " from get_single_install"); 
    avsignatures = defender_avsignatures;
    dbg::log(src:SCRIPT_NAME, msg:"Found avsignature " + avsignatures + " from get_single_install");
  }
}

if (isnull(path))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  audit(AUDIT_NOT_INST, "Forefront Endpoint Protection/System Center Endpoint Protection/Anti-malware Client/Windows Defender");
}

# Retrieve signature keys
signature_keys = make_list("SOFTWARE\Microsoft\Microsoft Antimalware",
                           "SOFTWARE\Microsoft\Windows Defender");
foreach sigkey (signature_keys)
{
  sigkey += '\\Signature Updates';
  key_h = RegOpenKey(handle:hklm, key:sigkey, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"AVSignatureVersion");
    if (!isnull(value))
    {
      dbg::log(src:SCRIPT_NAME, msg:"Found avsignature " + value[1] + " via " + sigkey + " registry keys.");
      if (empty_or_null(avsignatures))
      {
        dbg::log(src:SCRIPT_NAME, msg:"Setting avsignature found via " + sigkey + " registry keys.");
        avsignatures = value[1];
      }
      else
      {
        if (ver_compare(fix:avsignatures, ver:value[1]) == 1)
        {
          dbg::log(src:SCRIPT_NAME, msg:"Using more recent avsignature via " + sigkey + " registry keys.");
          avsignatures = value[1];
        }
        else
        {
          dbg::log(src:SCRIPT_NAME, msg:"Using previously found avsignature.");
        }
      }
    }
    value = RegQueryValue(handle:key_h, item:"ASSignatureVersion");
    if (!isnull(value))
    {
      dbg::log(src:SCRIPT_NAME, msg:"Found assignature " + value[1] + " via " + sigkey + " registry keys.");
      if (empty_or_null(assignatures))
      {
        dbg::log(src:SCRIPT_NAME, msg:"Setting assignature found via " + sigkey + " registry keys.");
        assignatures = value[1];
      }
      else
      {
        if (ver_compare(fix:assignatures, ver:value[1]) == 1)
        {
          dbg::log(src:SCRIPT_NAME, msg:"Using more recent assignature via " + sigkey + " registry keys.");
          assignatures = value[1];
        }
        else
        {
          dbg::log(src:SCRIPT_NAME, msg:"Using previously found assignature.");
        }
      }
    }

    value = RegQueryValue(handle:key_h, item:"EngineVersion");
    if (!isnull(value))
    {
      dbg::log(src:SCRIPT_NAME, msg:"Found engine_version " + value[1] + " via " + sigkey + " registry keys.");
      if (empty_or_null(engine_version))
      {
        dbg::log(src:SCRIPT_NAME, msg:"Setting engine_version found via " + sigkey + " registry keys.");
        engine_version = value[1];
      }
      else
      {
        if (ver_compare(fix:engine_version, ver:value[1]) == 1)
        {
          dbg::log(src:SCRIPT_NAME, msg:"Using more recent engine_version via " + sigkey + " registry keys.");
          engine_version = value[1];
        }
        else
        {
          dbg::log(src:SCRIPT_NAME, msg:"Using previously found engine_version.");
        }
      }
    }

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

# Grab the file version of file msseces.exe
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
if ("Antimalware" >< path)
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)\\Antimalware\\*", replace:"\1\msseces.exe", string:path);
else if(!isnull(scep_ver))
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\MSASCUI.exe", string:path);
else
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\msseces.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

ver  = NULL;
pname = NULL;

if (!isnull(fh))
{
  ret = GetFileVersionEx(handle:fh);
  if (!isnull(ret)) children = ret['Children'];

  if (!isnull(children))
  {
    varfileinfo = children['VarFileInfo'];
    if (!isnull(varfileinfo))
    {
      translation =
       (get_word (blob:varfileinfo['Translation'], pos:0) << 16) +
       get_word (blob:varfileinfo['Translation'], pos:2);
     translation = tolower(convert_dword(dword:translation, nox:TRUE));
    }
    stringfileinfo = children['StringFileInfo'];
    if (!isnull(stringfileinfo) && !isnull(translation))
    {
      data = stringfileinfo[translation];
      if (isnull(data)) data = stringfileinfo[toupper(translation)];
      if (!isnull(data))
      {
        ver    = data['FileVersion'];
        pname  = data['ProductName'];
        dbg::log(src:SCRIPT_NAME, msg:"Found version and product name via file properties on "+exe);
      }
    }
  }

  CloseFile(handle:fh);
}

NetUseDel();

# override with more descriptive info if possible
if(!isnull(scep_ver))
{
  ver = scep_ver;
  pname = "Managed Windows Defender";
}
else if(isnull(ver))
{
  path = defender_path;
  ver = defender_ver;
  engine_version = defender_engine_version;
  avsignatures = defender_avsignatures;
  pname = "Windows Defender";
}

report = NULL;
trouble = 0;

if(!isnull(ver))
{
  set_kb_item(name:"Antivirus/Forefront_Endpoint_Protection/installed", value:TRUE);
  set_kb_item(name:"Antivirus/Forefront_Endpoint_Protection/version", value:ver);
  set_kb_item(name:"Antivirus/Forefront_Endpoint_Protection/path", value:path);

  register_install(
    app_name:"Forefront Endpoint Protection",
    vendor : 'Microsoft',
    product : 'System Center Endpoint Protection',
    path:path,
    version:ver,
    extra:make_array("engine_version", engine_version,"av_sigs", avsignatures,"as_sigs", assignatures),
    cpe:"cpe:/a:microsoft:system_center_endpoint_protection"
  );

  if (isnull(pname))
    pname = 'Forefront Endpoint Protection';

  report = '\n' +
           "A Microsoft anti-malware product is installed on the remote host : " + '\n'+
           '\n' +
           "  Product name                  : " + pname + '\n' +
           "  Path                          : " + path + '\n' +
           "  Version                       : " + ver;

  if (!isnull(engine_version))
  {
    set_kb_item(name:"Antivirus/Forefront_Endpoint_Protection/engine_version", value:engine_version);
    report += '\n' +
              '  Engine version                : ' + engine_version ;
  }

  if (!isnull(avsignatures))
  {
    set_kb_item(name:"Antivirus/Forefront_Endpoint_Protection/av_sigs", value:avsignatures);
    report += '\n' +
              '  Antivirus signature version   : ' + avsignatures ;
  }

  if(!isnull(assignatures))
  {
    set_kb_item(name:"Antivirus/Forefront_Endpoint_Protection/as_sigs", value:assignatures);
    report += '\n' +
              '  Antispyware signature version : ' + assignatures ;
  }

  report += '\n';
}
else
{
  report += '\n' +
    'It was not possible to determine the installed version of Microsoft\n' +
    'Forefront Endpoint Protection / Anti-malware software.';

     trouble++;
}

info = get_av_info("fep");
if (isnull(info)) exit(1, "Failed to get Forefront Endpoint Protection info from antivirus.inc.");
latest_av_sigs = info["latest_av_sigs"];
latest_as_sigs = info["latest_as_sigs"];
latest_engine_version = info["latest_engine_version"];

if (!isnull(avsignatures))
{
  if (ver_compare(ver:avsignatures, fix:latest_av_sigs) == -1)
  {
    report += '\n' +
      'The antivirus signatures are out of date. The last known updated\n' +
      'version from the vendor is : ' +
      latest_av_sigs ;
    trouble++;
  }
}
else
{
 report += '\n' +
       "It was not possible to determine whether antivirus signatures are up to date.";
     trouble++;
}


if(!isnull(assignatures))
{
  if (ver_compare(ver:assignatures, fix:latest_as_sigs) == -1)
  {
    report += '\n' +
      'The antispyware signatures are out of date. The last known updated\n' +
      'version from the vendor is : ' +
      latest_as_sigs ;
    trouble++;
  }
}
else
{
 report += '\n' +
       "It was not possible to determine whether antispyware signatures are up to date.";
     trouble++;
}

# Check if engine version is out of date.

if(!isnull(engine_version))
{
  if (ver_compare(ver:engine_version, fix:latest_engine_version) == -1)
  {
    report += '\n' +
      'The antivirus engine version is out of date. The last known updated\n' +
      'version from the vendor is : ' +
      latest_engine_version ;
     trouble++;
  }
}
else
{
 report += '\n' +
       "It was not possible to determine the engine version for the antivirus software.";
     trouble++;
}

# - services running.
services = get_kb_item("SMB/svcs");
if (services)
{
  if(ver != scep_ver && ver != defender_ver)
    status = get_kb_item("SMB/svc/MsMpSvc");
  else if (!isnull(scep_ver) || !isnull(defender_ver))
    status = get_kb_item("SMB/svc/WinDefend");

  if(isnull(status))
  {
    report += '\n' +
      "The Microsoft Antimalware Service is not installed.";
    trouble++;
  }
  else if (status != SERVICE_ACTIVE)
  {
    report += '\n' +
      "The Microsoft Antimalware Service is not running.";
    trouble++;
  }
}
else
{
  report += 'Nessus was unable to retrieve a list of running services from the host.\n\n';
  trouble++;
}

set_kb_item(name:"Antivirus/Forefront_Endpoint_Protection/description", value:report);

if (trouble)
{
  report += '\n\n' +
    "As a result, the remote host might be infected by viruses received by
email or other means." +
   '\n';

  security_report_v4(port:port, extra:'\n' + report, severity:SECURITY_HOLE);
}
else
{
  exit(0, "Detected Microsoft Forefront Endpoint Protection/System Center Endpoint Protection/Anti-malware Client/Windows Defender with no known issues to report.");
}
