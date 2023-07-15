#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10785);
 script_version("1.54");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/20");

 script_name(english:"Microsoft Windows SMB NativeLanManager Remote System Information Disclosure");
 script_summary(english:"Extracts the remote native LAN manager name.");

 script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain information about the remote operating
system.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to obtain the remote operating system name and version
(Windows and/or Samba) by sending an authentication request to port
139 or 445. Note that this plugin requires SMB to be enabled on the
host.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2001/10/17");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"os_identification", value:"True");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Windows");

 script_dependencies("netbios_name_get.nasl", "samba_detect.nasl");
 script_require_ports(139,445, "/tmp/settings");
 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("ntlmssp.inc");

port = kb_smb_transport();

if (!smb_session_init(smb2:FALSE)) audit(AUDIT_FN_FAIL, 'smb_session_init');

r = NetUseAdd(share:"IPC$");
if (r == 1)
  NetUseDel();

if (!isnull(Session[17]))
{
  set_kb_item(name:"SMB/SMBv1_is_supported", value:TRUE);
  report = 'The remote Operating System is : ' + Session[17];
  if (!isnull(Session[18]))
    report += '\nThe remote native LAN manager is : ' + Session[18];
  if (!isnull(Session[19]))
    report += '\nThe remote SMB Domain Name is : ' + Session[19];

  report += '\n';

  if (!get_kb_item("SMB/workgroup") && Session[19] )
  {
   set_kb_item (name:"SMB/workgroup", value:Session[19]);
  }

  if ( Session[18] )
  {
   set_kb_item(name:"SMB/NativeLanManager", value:Session[18]);

   if (
    "Samba" >< Session[18] ||
    Session[18] == "NT1" ||
    "Isilon OneFS" >< Session[18] ||
    "Netreon LANMAN" >< Session[18]
   ) replace_kb_item(name:"SMB/not_windows", value:TRUE);
   # if this has a samba version create a kb item
   if ( "Samba" >< Session[18] ) set_kb_item(name:"SMB/Samba/version", value:Session[18]);
  }

  os = Session[17];

  if ("Windows NT" >< os)
    os = "Windows 4.0";
  else if ("Windows XP" >< os)
    os = "Windows 5.1";
  else if ("Windows Server 2003" >< os)
    os = "Windows 5.2";
  else if ("Vista" >< os)
    os = "Windows 6.0";
  else if (
    ("Windows Server 2008" >< os || "Windows Server (R) 2008" >< os)
    && "R2" >!< os
  )
    os = "Windows 6.0";
  else if ("Windows 7" >< os)
    os = "Windows 6.1";
  else if (
    ("Windows Server 2008" >< os || "Windows Server (R) 2008" >< os)
    && "R2" >< os
  )
    os = "Windows 6.1";
  else if ("Windows 8" >< os && "8.1" >!< os)
    os = "Windows 6.2";
  else if ("Windows Server 2012" >< os && "R2" >!< os)
    os = "Windows 6.2";
  else if ("Windows 8.1" >< os)
    os = "Windows 6.3";
  else if ("Windows Server 2012" >< os && "R2" >< os)
    os = "Windows 6.3";
  else if ("Windows 10" >< os && "Insider Preview" >< os)
    os = "Windows 6.3";
  else if ("Windows 10" >< os && "Insider Preview" >!< os)
    os = "Windows 10.0";

  if ( os )
  {
    set_kb_item(name:"Host/OS/smb", value:os);
    set_kb_item(name:"Host/OS/smb/Confidence", value:70);
    set_kb_item(name:"Host/OS/smb/Type", value:"general-purpose");

    if (
      "SpinStream2" >< os ||
      "EMC-SNAS" >< os ||
      "unix" >< tolower(os) ||
      "linux" >< tolower(os)
    ) replace_kb_item(name:"SMB/not_windows", value:TRUE);
  }
}
else
{
  set_kb_item(name:"SMB/SMBv1_is_supported", value:FALSE);
}

###
# Retrieve OS info from SMB2 if SMBv1 is not supported
###
if (!get_kb_item("SMB/SMBv1_is_supported"))
{
  NetUseDel();
  if (!smb_session_init(smb2:TRUE)) audit(AUDIT_FN_FAIL, 'smb_session_init');
  r = NetUseAdd(share:"IPC$");
  if (r == 1)
    NetUseDel();

  if (Session[24] == 1)
  {
    set_kb_item(name:"SMB/SMBv2_is_supported", value:TRUE);
    ntlm_sec_svc_provider = get_kb_item('SMB/NTLM Secure Service Provider');
    spad_log(message:'NTLM Security Service Provider: ' + obj_rep(ntlm_sec_svc_provider));

    if (!empty_or_null(ntlm_sec_svc_provider))
    {
      parser = new('ntlm_parser', hex2raw2(s:ntlm_sec_svc_provider));
      parser.parse();

      set_kb_item(name: 'SMB/'+port+'/NTLM/target_realm', value:parser.get('target_realm'));
      set_kb_item(name: 'SMB/'+port+'/NTLM/netbios_domain_name', value:parser.get('netbios_domain_name'));
      set_kb_item(name: 'SMB/'+port+'/NTLM/netbios_computer_name', value:parser.get('netbios_computer_name'));
      set_kb_item(name: 'SMB/'+port+'/NTLM/dns_domain_name', value:parser.get('dns_domain_name'));
      set_kb_item(name: 'SMB/'+port+'/NTLM/dns_computer_name', value:parser.get('dns_computer_name'));
      set_kb_item(name: 'SMB/'+port+'/NTLM/dns_tree_name', value:parser.get('dns_tree_name'));
      set_kb_item(name: 'SMB/'+port+'/NTLM/os_version', value:parser.get('os_version'));

      report = 'Nessus was able to obtain the following information about the host, by \n'
        + 'parsing the SMB2 Protocol\'s NTLM SSP message:\n'
        + '\n\tTarget Name: '+parser.get('target_realm')
        + '\n\tNetBIOS Domain Name: '+parser.get('netbios_domain_name')
        + '\n\tNetBIOS Computer Name: '+parser.get('netbios_computer_name')
        + '\n\tDNS Domain Name: '+parser.get('dns_domain_name')
        + '\n\tDNS Computer Name: '+parser.get('dns_computer_name')
        + '\n\tDNS Tree Name: '+parser.get('dns_tree_name')
        + '\n\tProduct Version: '+parser.get('os_version') + '\n';
    }
  }
  else
  {
    set_kb_item(name:"SMB/SMBv2_is_supported", value:FALSE);
  }
}

if (isnull(report))
  exit(0, "Host does not allow SMB.");

security_report_v4(severity:SECURITY_NOTE, port:port, extra:report);
