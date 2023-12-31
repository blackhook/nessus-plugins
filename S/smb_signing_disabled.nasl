##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(57608);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/05");

  script_name(english:"SMB Signing not required");

  script_set_attribute(attribute:"synopsis", value:
"Signing is not required on the remote SMB server.");
  script_set_attribute(attribute:"description", value:
"Signing is not required on the remote SMB server. An unauthenticated,
remote attacker can exploit this to conduct man-in-the-middle attacks
against the SMB server.");
  # https://support.microsoft.com/en-us/help/887429/overview-of-server-message-block-signing
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df39b8b3");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/library/cc731957.aspx");
  # http://technet.microsoft.com/en-us/library/cc786681%28WS.10%29.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74b80723");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html");
  # https://library.netapp.com/ecmdocs/ECMP1196993/html/GUID-084BBC00-EBD4-4899-AD85-9628368D3AF2.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a3cac4ea");
  script_set_attribute(attribute:"solution", value:
"Enforce message signing in the host's configuration. On Windows, this
is found in the policy setting 'Microsoft network server: Digitally
sign communications (always)'. On Samba, the setting is called 'server
signing'. See the 'see also' links for further details.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on analysis of vulnerability");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/19");

  script_set_attribute(attribute:"plugin_type", value: "remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/smb", 139, 445);
  exit(0);
}

include('byte_func.inc');
include('smb_func.inc');

# Get the smb port
port = kb_smb_transport();
if (!port) port = 139;

# Ensure the port is open.
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# Open a socket
s = open_sock_tcp(port);
if (!s) audit(AUDIT_SOCK_FAIL, port);

# Send the SMB_COM_NEGOTIATE packet
session_init(socket:s);
result = smb_negotiate_protocol(extended:TRUE);

if (s) close(s);
if (isnull(result)) audit(AUDIT_RESP_BAD, port);

protocol = ord(result);

# SMBv1
if (protocol == 0xFF)
{
  # Packet too small
  if (strlen(result) < SMB_HDR_SIZE + 1) audit(AUDIT_RESP_BAD, port);

  # If the negotiated dialect is NT LAN Manager, 
  # the structure of the SMB_COM_NEGOTIATE response is as follows.
  #
  #   SMB_Parameters
  #   {
  #     UCHAR  WordCount;          result[SMB_HDR_SIZE + 0x00]
  #     Words
  #     {
  #       USHORT   DialectIndex;   result[SMB_HDR_SIZE + 0x01]
  #       UCHAR    SecurityMode;   result[SMB_HDR_SIZE + 0x03]
  #       USHORT   MaxMpxCount;
  #       USHORT   MaxNumberVcs;
  #       ULONG    MaxBufferSize;
  #       ULONG    MaxRawSize;
  #       ULONG    SessionKey;
  #       ULONG    Capabilities;
  #       FILETIME SystemTime;
  #       SHORT    ServerTimeZone;
  #       UCHAR    ChallengeLength;
  #     }
  #   }
  #   SMB_Data
  #   {
  #     USHORT ByteCount;
  #     Bytes
  #   {
  #     UCHAR  Challenge[];
  #     SMB_STRING  DomainName[];
  #   }

  security_flags = get_byte(blob:result, pos:SMB_HDR_SIZE + 0x03);
  if (isnull(security_flags)) audit(AUDIT_RESP_BAD, port);

  if ((security_flags & NEGOTIATE_SECURITY_SIGNATURES_REQUIRED) == 0)
  {
    security_warning(port:port);
    exit(0);
  }
}
# SMBv2+
else if (protocol == 0xFE)
{
  # Packet too small
  if (strlen(result) < SMB2_HDR_SIZE + 1) audit(AUDIT_RESP_BAD, port);

  security_flags = get_word (blob:result, pos:SMB2_HDR_SIZE + 0x02);
  if (isnull(security_flags)) audit(AUDIT_RESP_BAD, port);

  if ((security_flags & SMB2_NEGOTIATE_SIGNING_REQUIRED) == 0)
  {
    security_warning(port:port);
    exit(0);
  }
}
# Unknown Protocol
else audit(AUDIT_RESP_BAD, port);

audit(AUDIT_HOST_NOT, 'affected');
