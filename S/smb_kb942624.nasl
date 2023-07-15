#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(29855);
 script_version("1.33");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

 script_cve_id("CVE-2007-5351");
 script_bugtraq_id(26777);
 script_xref(name:"MSFT", value:"MS07-063");
 script_xref(name:"IAVT", value:"2007-T-0049-S");
 script_xref(name:"MSKB", value:"942624");

 script_name(english:"MS07-063: Vulnerability in SMBv2 Could Allow Remote Code Execution (942624) (uncredentialed check)");
 script_summary(english:"Determines the presence of update 942624");

 script_set_attribute(attribute:"synopsis", value:"It is possible to execute arbitrary code on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of SMBv2 (Server
Message Block) protocol that is affected by several vulnerabilities.

An attacker may exploit these flaws to elevate his privileges and gain
control of the remote host.");
 # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2007/ms07-063
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec44f5b5");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows Vista.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-5351");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/12/11");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/12/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/07");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Windows");

 script_dependencies("smb_nativelanman.nasl");
 script_require_keys("Host/OS/smb");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("audit.inc");

os = get_kb_item ("Host/OS/smb") ;
if ( ! os || "Windows 6.0" >!< os ) audit(AUDIT_OS_NOT, "Windows Vista");

port = kb_smb_transport();

if (!smb_session_init(report_access_trouble:FALSE, report_auth_failure:FALSE)) audit(AUDIT_FN_FAIL, 'smb_session_init');

# We redefine the list of supported protocols by replacing smbv2.002 by smbv2.001
for (i = 0; i < max_index(protocol); i++)
{
  if (protocol[i] == "SMB 2.002")
  {
    protocol[i] = "SMB 2.001";
    break;
  }
}

ret = smb_negotiate_protocol (extended:FALSE);
if (!ret) audit(AUDIT_HOST_NOT, 'affected');

# Some checks in the header first
header = get_smb_header (smbblob:ret);
if (!header || strlen(header) < 4) audit(AUDIT_HOST_NOT, 'affected');

# If the host supports SMB 2.001, it will respond with an SMB2 protocol negotation
# response (starting with the bytes '0xFE', "SMB").
head = substr(header, 0, 3);
if (head == '\xfeSMB')
{
  security_hole(port);
}
else
{
  audit(AUDIT_HOST_NOT, 'affected');
}
