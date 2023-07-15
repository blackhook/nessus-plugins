#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118730);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/10");

  script_name(english:"Windows NetBIOS / SMB Remote Host Report Tag");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain the network name of the remote host.");
  script_set_attribute(attribute:"description", value:
"Either SMB or NetBIOS was used to determine the the device's
hostname.

Note that this plugin creates a tag for the host but does not
itself generate a report.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Windows");
  script_dependencies("netbios_name_get.nasl", "wmi_system_hostname.nbin", "microsoft_windows_nbt_info.nbin");

  exit(0);
}

netbios_hostname = get_kb_item('SMB/name');
from_netbios = get_kb_item('SMB/netbios_name');

wmi_hostname = get_kb_item('Host/hostname');
wmi_domain = get_kb_item('Host/WMI/Domain');
wmi_available = get_kb_item('SMB/WMI/Available');

if (!empty_or_null(wmi_domain))
{
  report_xml_tag(tag:'wmi-domain', value:wmi_domain);
  replace_kb_item(name:'Host/Tags/report/wmi-domain', value:wmi_domain);
}

# Credentialed Windows
if (!empty_or_null(wmi_hostname) && wmi_available)
{
  report_xml_tag(tag:'netbios-name', value:wmi_hostname);
  replace_kb_item(name:'Host/Tags/report/netbios-name', value:wmi_hostname);
}
# Remote SMB service
else if (!empty_or_null(netbios_hostname) && netbios_hostname != 'UNKNOWN[IP]' && from_netbios)
{
  report_xml_tag(tag:'netbios-name', value:netbios_hostname);
  replace_kb_item(name:'Host/Tags/report/netbios-name', value:netbios_hostname);
}
else
{
  exit(1, 'Unable to determine NetBIOS name.');
}
