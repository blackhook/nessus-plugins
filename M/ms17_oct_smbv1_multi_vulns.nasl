#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103876);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-11780", "CVE-2017-11781");
  script_bugtraq_id(101110, 101140);
  script_xref(name:"MSKB", value:"4041676");
  script_xref(name:"MSKB", value:"4041678");
  script_xref(name:"MSKB", value:"4041679");
  script_xref(name:"MSKB", value:"4041681");
  script_xref(name:"MSKB", value:"4041687");
  script_xref(name:"MSKB", value:"4041689");
  script_xref(name:"MSKB", value:"4041690");
  script_xref(name:"MSKB", value:"4041691");
  script_xref(name:"MSKB", value:"4041693");
  script_xref(name:"MSKB", value:"4041995");
  script_xref(name:"MSKB", value:"4042895");
  script_xref(name:"MSFT", value:"MS17-4041676");
  script_xref(name:"MSFT", value:"MS17-4041678");
  script_xref(name:"MSFT", value:"MS17-4041679");
  script_xref(name:"MSFT", value:"MS17-4041681");
  script_xref(name:"MSFT", value:"MS17-4041687");
  script_xref(name:"MSFT", value:"MS17-4041689");
  script_xref(name:"MSFT", value:"MS17-4041690");
  script_xref(name:"MSFT", value:"MS17-4041691");
  script_xref(name:"MSFT", value:"MS17-4041693");
  script_xref(name:"MSFT", value:"MS17-4041995");
  script_xref(name:"MSFT", value:"MS17-4042895");

  script_name(english:"Microsoft Windows SMB Server (2017-10) Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks response from SMBv1 server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by the following vulnerabilities :

  - A remote code execution vulnerability exists in the way
    that the Microsoft Server Message Block 1.0 (SMBv1)
    server handles certain requests. An attacker who
    successfully exploited the vulnerability could gain the
    ability to execute code on the target server.
    (CVE-2017-11780)

  - A denial of service vulnerability exists in the
    Microsoft Server Block Message (SMB) when an attacker
    sends specially crafted requests to the server. An
    attacker who exploited this vulnerability could cause
    the affected system to crash. To attempt to exploit this
    issue, an attacker would need to send specially crafted
    SMB requests to the target system. Note that the denial
    of service vulnerability would not allow an attacker to
    execute code or to elevate their user rights, but it
    could cause the affected system to stop accepting
    requests. The security update addresses the
    vulnerability by correcting the manner in which SMB
    handles specially crafted client requests.
    (CVE-2017-11781)

Note that Microsoft uses AC:H for these two vulnerabilities. This
could mean that an exploitable target is configured in a certain way
that may include that a publicly accessible file share is available
and share enumeration is allowed for anonymous users.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-11780
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72a4ce73");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-11781
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42adf289");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11780");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "smb_v1_enabled_remote.nasl", "smb_accessible_shares.nasl");
  script_require_keys("Host/OS", "SMB/SMBv1_is_supported", "SMB/accessible_shares/1");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("byte_func.inc");
include("global_settings.inc");
include("smb_func.inc");

function smb_get_error_code (data)
{
 local_var header, flags2, code;

 # Some checks in the header first
 header = get_smb_header (smbblob:data);
 if (!header)
   return NULL;

 flags2 = get_header_flags2 (header:header);
 if (flags2 & SMB_FLAGS2_32BIT_STATUS)
 {
   code = get_header_nt_error_code (header:header);
 }
 else
 {
   code = get_header_dos_error_code (header:header);
 }

 return code;
}


function my_smb_nt_trans(command, setup, param, data, max_pcount, max_dcount)
{
 local_var header, parameters, dat, packet, pad1, p_offset, d_offset, plen, dlen, slen, pad2; 

 pad1 = pad2 = NULL;

 header = smb_header (Command: SMB_COM_NT_TRANSACT,
                      Status: nt_status (Status: STATUS_SUCCESS));

 p_offset = 32 + 1 + 38 + strlen(setup) + 2 ;

 # Parameter is aligned to 4 byte
 pad1 = crap(data:'\x00', length: (4 - p_offset % 4) % 4);
 p_offset += strlen(pad1);

 # Data is aligned to 4 byte
 d_offset = p_offset + strlen (param);
 pad2 = crap(data:'\x00', length: (4 - d_offset % 4) % 4);
 d_offset += strlen(pad2);

 plen = strlen(param);
 dlen = strlen(data);
 slen = strlen(setup);

 if(slen % 2) return NULL; 

 if(isnull(max_pcount)) max_pcount = 0x1000;
 if(isnull(max_dcount)) max_dcount = 0x2000;

 parameters = 
	      raw_byte (b:256)          +   # Max setup count
        raw_word (w:0)            +   # Reserved1
        raw_dword (d:plen)        +   # total parameter count
	      raw_dword (d:dlen)        +   # total data count
	      raw_dword (d:max_pcount)  +   # Max parameter count
	      raw_dword (d:max_dcount)  +   # Max data count
	      raw_dword (d:plen)        +   # Parameter count
	      raw_dword (d:p_offset)    +   # Parameter offset
	      raw_dword (d:dlen)        +   # Data count
	      raw_dword (d:d_offset)    +   # Data offset
	      raw_byte (b:slen/2)       +   # Setup count
	      raw_word (w:command);         # Function 

 parameters += setup;

 parameters = smb_parameters (data:parameters);

 dat = pad1 +
       param +
       pad2 +
       data;

 dat = smb_data (data:dat);

 packet = netbios_packet (header:header, parameters:parameters, data:dat);

 return smb_sendrecv (data:packet);
}

function get_accessible_share()
{
  local_var arr, list, matches, ret, kb, kbs;
  local_var count, share, shares, login, pass;

  list = get_kb_list("SMB/accessible_shares/*");
  if (isnull(list)) return NULL;

  share = NULL;
  kbs = keys(list);
  foreach kb (kbs)
  {
    shares = list[kb];

    if("IPC$" >< toupper(shares))
      continue;

    arr = split(kb, sep:'/', keep: FALSE);
    if(max_index(arr) == 3 && (count = int(arr[2])))
    {
      matches = pregmatch(string:shares, pattern:'- *([^ -]+) *- *\\(');
      if(matches) 
      {
        share = matches[1]; 
        if(count == 1) 
        { 
          login = kb_smb_login();
          pass  = kb_smb_password();
        }
        else
        {
          login = get_kb_item("SMB/ValidUsers/" + count +  "/Login");
          pass  = get_kb_item("/tmp/SMB/ValidUsers/" + count + "/Password");
        }
        break;
      }
    }
  }

  if(share)
  {
    ret[0] =  share;
    ret[1] =  login;
    ret[2] =  pass;
    return ret;
  }
  else
    return NULL;
}

#
# MAIN
#

# Make sure it's Windows 
os = get_kb_item_or_exit("Host/OS");
if ("Windows" >!< os)
  audit(AUDIT_HOST_NOT, "Windows"); 

# Make sure SMBv1 is enabled
if (! get_kb_item("SMB/SMBv1_is_supported"))
  exit(0, "SMB version 1 does not appear to be enabled on the remote host."); 

if (!smb_session_init(smb2:FALSE)) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Get a accessible share
ret = get_accessible_share();
if(isnull(ret))
  exit(0, 'Nessus could not find an accessible share to test.');

# Connect to the share
share = ret[0];
login = ret[1];
pass  = ret[2];
dom   = kb_smb_domain();

r = NetUseAdd(share:share, login: login, password: pass, domain: dom);
if (r != 1) audit(AUDIT_SHARE_FAIL, share);

# Get a valid FID  
fh = CreateFile(file:"",
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if(isnull(fh)) exit(1, 'Failed to open a file on share "' + share + '".');
fid = fh[0];

# Perform the check
pat = 'AAAA';  # MUST be 4 bytes !
data = crap(data:pat, length:0x20);
setup =
  raw_dword (d:0x140078)  # FunctionCode
  + raw_word (w:fid)      # FID
  + raw_byte(b: 1)        # IsFsctl
  + raw_byte(b: 0);       # IsFlags

ret = my_smb_nt_trans(command:0x02,setup: setup, data: data, param:NULL);

CloseFile(handle:fh);
NetUseDel();

if(! isnull(ret))
{
  port = kb_smb_transport();
  status = smb_get_error_code (data:ret);
  if(status == STATUS_SUCCESS)
  {
    if (pat >< ret)
      security_report_v4(port: port, severity: SECURITY_WARNING);
    else
      audit(AUDIT_HOST_NOT , "affected");
  }
  else
  {
    status = "0x" + toupper(hexstr(mkdword(status)));
    audit(AUDIT_RESP_BAD, port, "an SMB_COM_NT_TRANSACT request. Status code: " + status);
  }
}
else
  exit(1, "Failed to get a response for an SMB_COM_NT_TRANSACT request.");
