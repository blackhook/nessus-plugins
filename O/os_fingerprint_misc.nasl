#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(65765);
  script_version("2.33");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/04");

  script_name(english:"OS Identification : Miscellaneous Methods");
  script_summary(english:"Identifies devices based on miscellaneous methods.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to identify the remote operating system based on
miscellaneous information.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to identify the remote operating system based on
miscellaneous sources of information.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies(
    "bigip_web_detect.nasl",
    "hp_laserjet_detect.nasl",
    "packeteer_web_detect.nasl",
    "smb_nativelanman.nasl",
    "wmi_available.nbin",
    "veritas_agent_detect.nasl",
    "wdb_agent_detect.nasl",
    "hp_lefthand_console_discovery.nasl",
    "hp_lefthand_hydra_detect.nasl",
    "hp_saniq_hydra_detect.nbin",
    "hp_data_protector_module_versions.nbin",
    "check_mk_detect.nasl",
    "vmware_vsphere_detect.nbin",
    "distro_guess.nasl",
    "quest_dr_series_web_detect.nbin",
    "pop3_ntlm_info.nasl",
    "nutanix_collect.nasl"
  );

  exit(0);
}

include('smb_func.inc');

function convert_win_ver_to_name(ver, sp)
{
  local_var os, os1, os2;

  os = "";
  if (ver =~ "^4\.0(\.|$)")
    os = "Microsoft Windows NT 4.0";
  else if (ver =~ "^5\.0(\.|$)")
    os = 'Microsoft Windows 2000\nNetApp';
  else if (ver =~ "^5\.1(\.|$)")
    os = 'Microsoft Windows XP\nMicrosoft Windows XP for Embedded Systems';
  else if (ver =~ "^5\.2(\.|$)")
    os = "Microsoft Windows Server 2003";
  else if (ver =~ "^6\.0(\.|$)")
    os = 'Microsoft Windows Vista\nMicrosoft Windows Server 2008';
  else if (ver =~ "^6\.1(\.|$)")
    os = 'Microsoft Windows 7\nMicrosoft Windows Server 2008 R2';
  else if (ver =~ "^6\.2(\.|$)")
    os = 'Microsoft Windows 8\nMicrosoft Windows Server 2012';
  else if (ver =~ "^6\.3(\.|$)")
    os = 'Microsoft Windows 8.1\nMicrosoft Windows Server 2012 R2\nMicrosoft Windows 10 Enterprise Insider Preview';
  else if (ver =~ "^10\.0(\.|$)")
    os = 'Windows 10 Home\nWindows 10 Pro\nWindows 10 Pro Education\nWindows 10 Enterprise\nWindows 10 Enterprise LTSB\nWindows 10 Education\nWindows 10 IoT Core\nWindows 10 IoT Enterprise\nWindows 10 S';

  if (os && sp)
  {
    os2 = "";
    foreach os1 (split(os, keep:FALSE))
    {
      os2 += os1 + ' Service Pack ' + sp + '\n';
    }
    os = chomp(os2);
  }

  return os;
}

kb_base = "Host/OS/Misc";              # nb: should *not* end with a slash

if (
  get_kb_item("Services/cpfw1") ||
  get_kb_item("Services/fw1_generic") ||
  get_kb_item("Services/cp_ica")
)
{
  set_kb_item(name:kb_base, value:"Check Point GAiA");
  set_kb_item(name:kb_base+"/Confidence", value:70);
  set_kb_item(name:kb_base+"/Type", value:"firewall");
  exit(0);
}

item = get_kb_item("www/hp_laserjet/pname");
if (!isnull(item))
{
  match = pregmatch(pattern:'^(HP (Color LaserJet|Digital Sender|LaserJet) [A-Za-z0-9]+)', string:item);
  if (match)
  {
    os = match[1];

    item2 = get_kb_item("www/hp_laserjet/fw");
    if (!isnull(item2))
    {
      match2 = pregmatch(pattern:'([\\d]{8}([\\s]+[\\d]+.[\\d]+.[\\d]+)?)', string:item2);
      if (match2) os += ' with firmware version ' + match2[1];
    }

    set_kb_item(name:kb_base, value:os);
    set_kb_item(name:kb_base+"/Confidence", value:99);
    set_kb_item(name:kb_base+"/Type", value:"printer");
    exit(0);
  }
}

item = get_kb_item("www/bigip");
if (!isnull(item))
{
  set_kb_item(name:kb_base, value:"F5 Networks BIG-IP");
  set_kb_item(name:kb_base+"/Confidence", value:75);
  set_kb_item(name:kb_base+"/Type", value:"load-balancer");
}

xnm_list = get_kb_list("Services/xnm");
if (!isnull(xnm_list))
{
  # nb: we should need the banner from just one of these.
  foreach var p (xnm_list)
  {
    b = get_kb_item("xnm/banner/"+p);
    if (!isnull(b))
    {
      match = pregmatch(pattern:'os="JUNOS" release="([0-9][^"]+)" hostname=', string:b);
      if (!isnull(match))
      {
        os = "Juniper Junos Version " + match[1];

        set_kb_item(name:kb_base, value:os);
        set_kb_item(name:kb_base+"/Confidence", value:95);
        set_kb_item(name:kb_base+"/Type", value:"embedded");
        exit(0);
      }
    }
  }
}

item = get_kb_item("www/443/packeteer");
if (!isnull(item) && "PacketShaper" == item)
{
  set_kb_item(name:kb_base, value:"Blue Coat PacketShaper");
  set_kb_item(name:kb_base+"/Confidence", value:75);
  set_kb_item(name:kb_base+"/Type", value:"embedded");
}

item = get_kb_item("Host/Veritas/BackupExecAgent/OS_Type");
if (!isnull(item))
{
  item2 = get_kb_item("Host/Veritas/BackupExecAgent/OS_Version");
  if ("Windows" >< item && "Major Version=" >< item2)
  {
    match = pregmatch(pattern:'Major Version=([0-9]+) Minor Version=([0-9]+) Build Number=([0-9]+) ServicePack Major=([0-9]+) ServicePack Minor=([0-9]+) SuiteMask=([0-9]+) ProductType=([0-9]+) ProcessorType=(.+)$', string:item2);
    if (!isnull(match))
    {
      os = convert_win_ver_to_name(ver:match[1]+"."+match[2], sp:int(match[4]));
      confidence = 80;
      if ('\n' >< os) confidence -= 10;

      set_kb_item(name:kb_base, value:os);
      set_kb_item(name:kb_base+"/Confidence", value:confidence);
      set_kb_item(name:kb_base+"/Type", value:"embedded");
      exit(0);
    }
  }
}

item = get_kb_item("Host/OS/smb");
if (!isnull(item))
{
  if ("EMC-SNAS" >< item)
  {
    set_kb_item(name:kb_base, value:"EMC Celerra File Server");
    set_kb_item(name:kb_base+"/Confidence", value:95);
    set_kb_item(name:kb_base+"/Type", value:"embedded");
    exit(0);
  }
  else if ("Windows " >< item)
  {
    item = chomp(item) - "Windows ";
    os = convert_win_ver_to_name(ver:item);
    if (empty_or_null(os))
    {
      if ('Microsoft' >!< item)
        os = 'Microsoft Windows ' + item;
    }

    if ("Windows " >< os)
    {

      ##
      #  Exception for Windows 11
      #
      #  - This check requires credentials -
      #  If creds are provided, KB item 'WMI/Host/OS' may have been
      #  created by nbin/dcom/wmi_available.nasl
      #
      #  This condition should be applied to Windows11.
      #  A similar check appears farther below
      #  if this check is unmatched and 
      #  if KB "SMB/name" is found
      ##
      item = get_kb_item("WMI/Host/OS");
      if (!empty_or_null(item))
      {
        if ("Windows 11" >< item)
        {
          set_kb_item(name:kb_base, value:item);
          # conf 100 result found associated with SMB_OS, must use 101
          set_kb_item(name:kb_base+"/Confidence", value:101);
          set_kb_item(name:kb_base+"/Type", value:"general-purpose");
          exit(0);
        }
      }

      confidence = 80;
      if ('\n' >< os) confidence -= 10;

      set_kb_item(name:kb_base, value:os);
      set_kb_item(name:kb_base+"/Confidence", value:confidence);
      set_kb_item(name:kb_base+"/Type", value:"general-purpose");
      exit(0);
    }
  }
  else if ("SunOS" >< item)
  {
    os = "Solaris";
    confidence = 70;

    # E.g. SunOS 5.11 11.3
    matches = pregmatch(string:item, pattern:"^SunOS +([0-9.]+)(?: +([0-9.]+))?");
    if (!empty_or_null(matches))
    {
      if (!empty_or_null(matches[2]))
      {
        os += " " + matches[2];
        confidence = 90;
      }
      # If the Solaris version isn't available (e.g. SunOS 5.11),
      # try to deduce Solaris version from SunOS version
      else
      {
        if      (matches[1] == '5.11')  os += " 11";
        else if (matches[1] == '5.10')  os += " 10";
        else if (matches[1] == '5.9')   os += " 9";
        else if (matches[1] == '5.8')   os += " 8";
        else if (matches[1] == '5.7')   os += " 7";
        else if (matches[1] == '5.6')   os += " 2.6";
        else if (matches[1] == '5.5.1') os += " 2.5.1";
        else if (matches[1] == '5.5')   os += " 2.5";
        else if (matches[1] == '5.4')   os += " 2.4";
        else if (matches[1] == '5.3')   os += " 2.3";
        else if (matches[1] == '5.2')   os += " 2.2";
        else if (matches[1] == '5.1')   os += " 2.1";
        else if (matches[1] == '5.0')   os += " 2.0";

        if (os =~ "[0-9]$") confidence = 90;

        # More granular versions of the 11 branch (e.g. 11.3) exist but
        # we can't deduce it from the SunOS version so lower confidence
        if (os == "Solaris 11") confidence -= 10;
      }
    }

    set_kb_item(name:kb_base, value:os);
    set_kb_item(name:kb_base+"/Confidence", value:confidence);
    set_kb_item(name:kb_base+"/Type", value:"general-purpose");
    exit(0);
  } 
}

item = get_kb_item("Host/VxWorks/RunTimeVersion");
if (!isnull(item))
{
  if ("VxWorks" >< item)
  {
    os = "VxWorks";

    match = pregmatch(pattern:'VxWorks[ \t]*([0-9][0-9.]+)', string:item);
    if (!isnull(match)) os += ' ' + match[1];

    set_kb_item(name:kb_base, value:os);
    set_kb_item(name:kb_base+"/Confidence", value:74);
    set_kb_item(name:kb_base+"/Type", value:"embedded");
    exit(0);
  }
}

item = get_kb_item("HP/LeftHandOS");
if(!isnull(item))
{
  set_kb_item(name:kb_base, value:"HP LeftHand OS");
  set_kb_item(name:kb_base+"/Confidence", value:99);
  set_kb_item(name:kb_base+"/Type", value:"embedded");
  exit(0);
}

# HP Data Protector puts OS information in patch info string
# e.g -os "microsoft i386 wNT-5.2-S"
item = get_kb_item("Services/data_protector/patch_info_str");
res = pregmatch(pattern:'-[oO][sS] "([^"]+)"', string:item);
if (isnull(res))
{
  item = get_kb_item("Services/data_protector/patch_info_is_str");
  res = pregmatch(pattern:'-[oO][sS] "([^"]+)"', string:item);
}

if (!isnull(res))
{
  os_str = tolower(res[1]);

  # Windows
  # microsoft i386 wNT-5.2-S
  item = pregmatch(pattern:"^microsoft .+ wnt-([0-9.]+)-[swu]$", string:os_str);
  if (!isnull(item) && !isnull(item[1]))
  {
    os = convert_win_ver_to_name(ver:item[1]);
    if (os != "")
    {
      confidence = 80;
      if ('\n' >< os) confidence -= 10;

      set_kb_item(name:kb_base, value:os);
      set_kb_item(name:kb_base+"/Confidence", value:confidence);
      set_kb_item(name:kb_base+"/Type", value:"general-purpose");
      exit(0);
    }
  }

  # Linux
  # gpl x86_64 linux-2.6.18-194.el5
  item = pregmatch(pattern:"^gpl .+ linux-([0-9.]+)([^0-9.].*)?$", string:os_str);
  if (!isnull(item))
  {
    os = "Linux Kernel " + item[1];
    confidence = 70;
    set_kb_item(name:kb_base, value:os);
    set_kb_item(name:kb_base+"/Confidence", value:confidence);
    set_kb_item(name:kb_base+"/Type", value:"general-purpose");
    exit(0);
  }

  # HP-UX
  # hp s800 hp-ux-11.00
  item = pregmatch(pattern:"^hp .+ hp-ux-([0-9.]+)$", string:os_str);
  if (!isnull(item))
  {
    os = "HP-UX " + item[1];
    confidence = 70;
    set_kb_item(name:kb_base, value:os);
    set_kb_item(name:kb_base+"/Confidence", value:confidence);
    set_kb_item(name:kb_base+"/Type", value:"general-purpose");
    exit(0);
  }

  # Solaris
  # sun sparc solaris-5.8
  item = pregmatch(pattern:"^sun .+ solaris-([0-9.]+)$", string:os_str);
  if (!isnull(item))
  {
    os = "Solaris " + item[1];
    confidence = 70;
    set_kb_item(name:kb_base, value:os);
    set_kb_item(name:kb_base+"/Confidence", value:confidence);
    set_kb_item(name:kb_base+"/Type", value:"general-purpose");
    exit(0);
  }

  # Using info from Check_MK Agent
  item = get_kb_item("Check_MK/Installed");
  if(!isnull(item))
  {
    os = get_kb_item("Check_MK/" + item + "/AgentOS");
    if(!isnull(os))
    {
      confidence = 70; 
      set_kb_item(name:kb_base, value:os);
      set_kb_item(name:kb_base+"/Confidence", value:confidence);
      set_kb_item(name:kb_base+"/Type", value:"general-purpose");
    }
  }
}

item = get_kb_item("Host/VMware/release");
if (!isnull(item))
{
  confidence = 98;
  set_kb_item(name:kb_base, value:item);
  set_kb_item(name:kb_base+"/Confidence", value:confidence);
  set_kb_item(name:kb_base+"/Type", value:"hypervisor");
}

# Dell / Quest DR Series Appliance
item = get_kb_item("Host/Quest DR Series Appliance/version");
if (!empty_or_null(item))
{
  os = "Quest DR Series Appliance";

  model = get_kb_item("Host/Quest DR Series Appliance/model");
  if (!empty_or_null(model))
  {
    # The product_name appears to always contain "Dell" when developed under Dell
    # and omits the vendor name when Quest split off from Dell
    if (model =~ "^(Dell|Quest)")
      os = model;
    else
      os = "Quest " + model;
  }

  os += " " + item;

  confidence = 98;
  set_kb_item(name:kb_base, value:os);
  set_kb_item(name:kb_base+"/Confidence", value:confidence);
  set_kb_item(name:kb_base+"/Type", value:"embedded");
  exit(0);
}

items = get_kb_list("pop3/*/ntlm/host/os_version");
if (!empty_or_null(items))
{
  foreach item (items)
  {
    os = convert_win_ver_to_name(ver:item[1]);
    if (os != "")
    {
      confidence = 80;
      if ('\n' >< os) confidence -= 10;

      set_kb_item(name:kb_base, value:os);
      set_kb_item(name:kb_base+"/Confidence", value:confidence);
      set_kb_item(name:kb_base+"/Type", value:"general-purpose");
      exit(0);
    }
  }
}

# NetApp
items = get_kb_list("Services/netapp_ndmp");
if (!empty_or_null(items))
{
  ##
  #  CS-35070 - Sometimes NetApp incorrectly
  #   detected as unsupported FreeBSD because of SSH banner.
  #   Limit to reported port / SSH fingerprint combo
  ##
  os = 0;            # reuse var
  foreach item (items)
    if ('10000' >< item)
      os = 1;

  item = get_kb_item("SSH/banner/22");
  if (os && 
      !empty_or_null(item) && 
      item == 'SSH-2.0-OpenSSH_7.2 FreeBSD-20160310')
  {
    set_kb_item(name:kb_base, value:"NetApp Appliance");
    set_kb_item(name:kb_base+"/Confidence", value:86);
    set_kb_item(name:kb_base+"/Type", value:"embedded");
    exit(0); 
  }
  else
  {
    set_kb_item(name:kb_base, value:"NetApp Appliance");
    set_kb_item(name:kb_base+"/Confidence", value:75);
    set_kb_item(name:kb_base+"/Type", value:"embedded");
    exit(0); 
  }
}

# Default to Windows if SMB name is available
# and SMB/not_windows is not present
item = get_kb_item("SMB/name");
if (!empty_or_null(item) && !get_kb_item("SMB/not_windows"))
{

  ##
  #  Exception for Windows 11
  #
  #  - This check requires credentials -
  #  If creds are provided, KB item 'WMI/Host/OS' may have been
  #  created by nbin/dcom/wmi_available.nasl
  #
  #  This condition should apply to Windows 11 but not Windows 10
  #  because this code will only look for Windows 11 below, and
  #  Windows 10 is handled above
  ##
  item = get_kb_item("WMI/Host/OS");
  if (!empty_or_null(item))
  {
    if ("Windows 11" >< item)
    {
      set_kb_item(name:kb_base, value:item);
      # conf 100 result found associated with SMB_OS, must use 101
      set_kb_item(name:kb_base+"/Confidence", value:101);
      set_kb_item(name:kb_base+"/Type", value:"general-purpose");
      exit(0);
    }
  }

  ##
  #  Exception for Windows 11
  #
  #  - This check does not require credentials -
  #  Without credentials, plugin
  #  plugins/Windows/s/smb_nativelanman.nasl
  #  is able to report the following versions:
  #  Windows 10         : 10.0.19041
  #  Windows 11 Preview : 10.0.22000
  #  * This code may result in FP if Win10 subver goes above 22000,
  #    however Win10 is handled in a function above and should be excluded,
  #    because it has KB 'Host/OS/smb' and not 'SMB/445/NTLM/os_version'
  ##
  winport = kb_smb_transport();
  if (!winport) 
    winport = get_one_kb_item('SMB/*/NTLM/os_version');

  item = get_kb_item('SMB/' + winport + '/NTLM/os_version');
  if (!empty_or_null(item))
  {
    item = split(item, sep:'.', keep:FALSE);
    if (!empty_or_null(item) &&
        !empty_or_null(item[0]) &&
        !empty_or_null(item[2]) &&
        item[0] >= 10 &&
        item[2] >= 22000)
    {
      set_kb_item(name:kb_base, value:"Windows 11");
      set_kb_item(name:kb_base+"/Confidence", value:70);
      set_kb_item(name:kb_base+"/Type", value:"general-purpose");
      exit(0);
    }
  }

  ##
  #  Seems to be Windows, but unmatched in the code above
  ##
  set_kb_item(name:kb_base, value:"Windows");
  set_kb_item(name:kb_base+"/Confidence", value:50);
  set_kb_item(name:kb_base+"/Type", value:"general-purpose");
  exit(0);
}

# Nutanix
var nserv = get_kb_item("Host/Nutanix/Data/Service");
var nver = get_kb_item("Host/Nutanix/Data/Version");

if (!empty_or_null(nver) || !empty_or_null(nserv))
{
  var nextra = 'Nutanix';

  if (!empty_or_null(nserv))
    nextra = strcat(nextra, " ", nserv);
  if (!empty_or_null(nver))
    nextra = strcat(nextra, " ", nver);

  set_kb_item(name:kb_base, value:nextra);

  set_kb_item(name:kb_base+"/Confidence", value:86);
  set_kb_item(name:kb_base+"/Type", value:"general-purpose");
  exit(0); 
}


exit(0, "Nessus was not able to identify the OS from miscellaneous methods.");
