###
# (C) Tenable Network Security, Inc.
###

include("compat.inc");

if (description)
{
  script_id(34097);
  script_version("1.9");
  script_cvs_date("Date: 2018/11/01 16:40:18");
  script_name(english:"BIOS Info (SMB)");
  script_summary(english:"Use SMB to get BIOS info");

  script_set_attribute(attribute:"synopsis", value:"BIOS info could be read.");
  script_set_attribute(attribute:"description", value: "It is possible to get information about the BIOS via the host's SMB interface.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/08");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Windows");
  script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_access.nasl", "bios_get_info_wmi.nbin");
  script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
  # if any of these values are set then this plugin won't run (most likely already found values in WMI plugin)
  script_exclude_keys("BIOS/Vendor", "BIOS/Version", "BIOS/ReleaseDate", "BIOS/SecureBoot");
  script_require_ports(139, 445);
  exit(0);
}

# using SMB registry include file
include("global_settings.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("audit.inc");

# do ALL of the KB values we know how to fetch exist?
if ( get_kb_item("BIOS/Version") &&
     get_kb_item("BIOS/ReleaseDate") &&
     get_kb_item("BIOS/SecureBoot") )
{
  # ALL of the KB values we know how to fetch exist, exit
  exit(0, "BIOS information already collected according to KB items." );
}

# do simple registry access, ok to exit if any failures occur
registry_init(full_access_check:FALSE);
# connect to HKLM hive, ok to exit on fail
hklm=registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
if ( isnull(hklm) )
{
  audit( AUDIT_REG_FAIL );
}
# get the values we need, only 3 so lets keep it simple here
biosVersion=get_registry_value(handle:hklm, item:"Hardware\Description\System\SystemBiosVersion");
biosDate=get_registry_value(handle:hklm, item:"Hardware\Description\System\SystemBiosDate");
bootSecure=get_registry_value(handle:hklm, item:"System\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled");
# done with registry
RegCloseKey(handle:hklm);
close_registry();

# did any of this work?
if ( empty_or_null(biosVersion) && empty_or_null(biosDate) && empty_or_null(bootSecure) )
{
  # no, fail, this path helps with secure boot reporting later
  exit(0, "The SMB query did not return any results.");
}

# did we get a value?
if ( empty_or_null(biosVersion) )
{
  # no, make something up for the report
  biosVersion = "n/a";
}
else
{
  # got a value, does value exist in KB?
  if (empty_or_null(get_kb_item("BIOS/Version")))
  {
    # no value exist in KB, update KB
    replace_kb_item( name: "BIOS/Version", value: biosVersion );
  }
}

# did we get a value?
if ( empty_or_null(biosDate) )
{
  # no, make something up for the report
  biosDate = "n/a";
}
else
{
  # got a value, does value exist in KB?
  if (empty_or_null(get_kb_item("BIOS/ReleaseDate")))
  {
    # no value exist in KB, update KB
    replace_kb_item( name: "BIOS/ReleaseDate", value: biosDate );
  }
}

# did we get a value?
if ( empty_or_null(bootSecure) )
{
  # no, report secure boot is disabled because we know registry is
  # working (it returned other values)
  bootSecure = "disabled";
}
else
{
  # got a value, is it 0 (disabled)?
  if ( bootSecure == "0" )
  {
    # yes value is 0, indicate secure boot is disabled
    bootSecure = "disabled";
  }
  else
  {
    # no value is not 0, indicate secure boot is enabled
    bootSecure = "enabled";
  }
}

# does value exist in KB?
if (empty_or_null(get_kb_item("BIOS/SecureBoot")))
{
  # no value exist in KB, update KB
  replace_kb_item( name: "BIOS/SecureBoot", value: bootSecure );
}

# create report
report = '\n  Version      : ' + biosVersion +
         '\n  Release date : ' + biosDate +
         '\n  Secure boot  : ' + bootSecure + '\n';
security_report_v4(port: 0, severity:SECURITY_NOTE, extra:report);
