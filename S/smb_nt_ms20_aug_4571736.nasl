#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(139493);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/23");

  script_cve_id(
    "CVE-2020-1046",
    "CVE-2020-1337",
    "CVE-2020-1339",
    "CVE-2020-1377",
    "CVE-2020-1378",
    "CVE-2020-1379",
    "CVE-2020-1380",
    "CVE-2020-1383",
    "CVE-2020-1464",
    "CVE-2020-1466",
    "CVE-2020-1467",
    "CVE-2020-1472",
    "CVE-2020-1473",
    "CVE-2020-1474",
    "CVE-2020-1475",
    "CVE-2020-1476",
    "CVE-2020-1477",
    "CVE-2020-1478",
    "CVE-2020-1485",
    "CVE-2020-1486",
    "CVE-2020-1488",
    "CVE-2020-1489",
    "CVE-2020-1509",
    "CVE-2020-1513",
    "CVE-2020-1515",
    "CVE-2020-1517",
    "CVE-2020-1518",
    "CVE-2020-1519",
    "CVE-2020-1520",
    "CVE-2020-1529",
    "CVE-2020-1530",
    "CVE-2020-1537",
    "CVE-2020-1538",
    "CVE-2020-1554",
    "CVE-2020-1557",
    "CVE-2020-1558",
    "CVE-2020-1562",
    "CVE-2020-1564",
    "CVE-2020-1565",
    "CVE-2020-1567",
    "CVE-2020-1570",
    "CVE-2020-1577",
    "CVE-2020-1579",
    "CVE-2020-1584",
    "CVE-2020-1587"
  );
  script_xref(name:"IAVA", value:"0001-A-0647");
  script_xref(name:"IAVA", value:"2020-A-0367-S");
  script_xref(name:"IAVA", value:"2020-A-0438-S");
  script_xref(name:"IAVA", value:"2021-A-0429-S");
  script_xref(name:"IAVA", value:"2021-A-0431-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2020/09/21");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"MSKB", value:"4571702");
  script_xref(name:"MSKB", value:"4571736");
  script_xref(name:"MSFT", value:"MS20-4571702");
  script_xref(name:"MSFT", value:"MS20-4571736");
  script_xref(name:"CISA-NCAS", value:"AA22-011A");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2020-0101");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0008");
  script_xref(name:"CEA-ID", value:"CEA-2020-0121");
  script_xref(name:"CEA-ID", value:"CEA-2023-0016");

  script_name(english:"KB4571702: Windows Server 2012 August 2020 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4571702
or cumulative update 4571736. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability exists when
    Windows Media Audio Codec improperly handles objects. An
    attacker who successfully exploited the vulnerability
    could take control of an affected system. There are
    multiple ways an attacker could exploit the
    vulnerability, such as by convincing a user to open a
    specially crafted document, or by convincing a user to
    visit a malicious webpage. The security update addresses
    the vulnerability by correcting how Windows Media Audio
    Codec handles objects. (CVE-2020-1339)

  - An elevation of privilege vulnerability exists in the
    way that the srmsvc.dll handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2020-1475)

  - An information disclosure vulnerability exists when
    DirectWrite improperly discloses the contents of its
    memory. An attacker who successfully exploited the
    vulnerability could obtain information to further
    compromise the users system. There are multiple ways an
    attacker could exploit the vulnerability, such as by
    convincing a user to open a specially crafted document,
    or by convincing a user to visit an untrusted webpage.
    The security update addresses the vulnerability by
    correcting how DirectWrite handles objects in memory.
    (CVE-2020-1577)

  - An information disclosure vulnerability exists in RPC if
    the server has Routing and Remote Access enabled. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system  (CVE-2020-1383)

  - A memory corruption vulnerability exists when Windows
    Media Foundation improperly handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could install programs; view, change, or delete data; or
    create new accounts with full user rights. There are
    multiple ways an attacker could exploit the
    vulnerability, such as by convincing a user to open a
    specially crafted document, or by convincing a user to
    visit a malicious webpage. The security update addresses
    the vulnerability by correcting how Windows Media
    Foundation handles objects in memory. (CVE-2020-1379,
    CVE-2020-1477, CVE-2020-1478, CVE-2020-1554)

  - An elevation of privilege vulnerability exists when the
    Windows kernel fails to properly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could run arbitrary code in kernel mode.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights.  (CVE-2020-1486)

  - An elevation of privilege vulnerability exists when the
    Windows CSC Service improperly handles memory.
    (CVE-2020-1489, CVE-2020-1513)

  - An elevation of privilege vulnerability exists when
    Windows improperly handles hard links. An attacker who
    successfully exploited this vulnerability could
    overwrite a targeted file leading to an elevated status.
    (CVE-2020-1467)

  - A denial of service vulnerability exists in Windows
    Remote Desktop Gateway (RD Gateway) when an attacker
    connects to the target system using RDP and sends
    specially crafted requests. An attacker who successfully
    exploited this vulnerability could cause the RD Gateway
    service on the target system to stop responding.
    (CVE-2020-1466)

  - An elevation of privilege vulnerability exists in the
    Local Security Authority Subsystem Service (LSASS) when
    an authenticated attacker sends a specially crafted
    authentication request. A remote attacker who
    successfully exploited this vulnerability could cause an
    elevation of privilege on the target system's LSASS
    service. The security update addresses the vulnerability
    by changing the way that LSASS handles specially crafted
    authentication requests. (CVE-2020-1509)

  - A remote code execution vulnerability exists when the
    Windows Font Driver Host improperly handles memory. An
    attacker who successfully exploited the vulnerability
    would gain execution on a victim system. The security
    update addresses the vulnerability by correcting how the
    Windows Font Driver Host handles memory. (CVE-2020-1520)

  - An elevation of privilege vulnerability exists when the
    Windows UPnP Device Host improperly handles memory.
    (CVE-2020-1519, CVE-2020-1538)

  - An elevation of privilege vulnerability exists when the
    Windows Telephony Server improperly handles memory.
    (CVE-2020-1515)

  - An elevation of privilege vulnerability exists when the
    Windows File Server Resource Management Service
    improperly handles memory.  (CVE-2020-1517,
    CVE-2020-1518)

  - An elevation of privilege vulnerability exists in the
    way that the dnsrslvr.dll handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2020-1584)

  - An elevation of privilege vulnerability exists when the
    &quot;Public Account Pictures&quot; folder improperly
    handles junctions.  (CVE-2020-1565)

  - An elevation of privilege vulnerability exists when the
    Windows Remote Access improperly handles file
    operations. An attacker who successfully exploited this
    vulnerability could gain elevated privileges.
    (CVE-2020-1537)

  - An elevation of privilege vulnerability exists when an
    attacker establishes a vulnerable Netlogon secure
    channel connection to a domain controller, using the
    Netlogon Remote Protocol (MS-NRPC). An attacker who
    successfully exploited the vulnerability could run a
    specially crafted application on a device on the
    network.  (CVE-2020-1472)

  - An elevation of privilege vulnerability exists when the
    Windows Kernel API improperly handles registry objects
    in memory. An attacker who successfully exploited the
    vulnerability could gain elevated privileges on a
    targeted system. A locally authenticated attacker could
    exploit this vulnerability by running a specially
    crafted application. The security update addresses the
    vulnerability by helping to ensure that the Windows
    Kernel API properly handles objects in memory.
    (CVE-2020-1377, CVE-2020-1378)

  - An elevation of privilege vulnerability exists when the
    Windows Print Spooler service improperly allows
    arbitrary writing to the file system. An attacker who
    successfully exploited this vulnerability could run
    arbitrary code with elevated system privileges. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights.  (CVE-2020-1337)

  - An information disclosure vulnerability exists when the
    Windows Image Acquisition (WIA) Service improperly
    discloses contents of its memory. An attacker who
    successfully exploited the vulnerability could obtain
    information to further compromise the users system.
    (CVE-2020-1474, CVE-2020-1485)

  - An elevation of privilege vulnerability exists when the
    Windows Ancillary Function Driver for WinSock improperly
    handles memory.  (CVE-2020-1587)

  - A remote code execution vulnerability exists when the
    Windows Jet Database Engine improperly handles objects
    in memory. An attacker who successfully exploited this
    vulnerability could execute arbitrary code on a victim
    system. An attacker could exploit this vulnerability by
    enticing a victim to open a specially crafted file. The
    update addresses the vulnerability by correcting the way
    the Windows Jet Database Engine handles objects in
    memory. (CVE-2020-1473, CVE-2020-1557, CVE-2020-1558,
    CVE-2020-1564)

  - A remote code execution vulnerability exists when
    Microsoft .NET Framework processes input. An attacker
    who successfully exploited this vulnerability could take
    control of an affected system.  (CVE-2020-1046)

  - A remote code execution vulnerability exists in the way
    that the MSHTML engine improperly validates input. An
    attacker could execute arbitrary code in the context of
    the current user.  (CVE-2020-1567)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Graphics Device Interface (GDI)
    handles objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2020-1529)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2020-1380, CVE-2020-1570)

  - An elevation of privilege vulnerability exists when the
    Windows AppX Deployment Extensions improperly performs
    privilege management, resulting in access to system
    files.  (CVE-2020-1488)

  - An elevation of privilege vulnerability exists when the
    Windows Function Discovery SSDP Provider improperly
    handles memory.  (CVE-2020-1579)

  - An elevation of privilege vulnerability exists when
    ASP.NET or .NET web applications running on IIS
    improperly allow access to cached files. An attacker who
    successfully exploited this vulnerability could gain
    access to restricted files.  (CVE-2020-1476)

  - An elevation of privilege vulnerability exists when
    Windows Remote Access improperly handles memory.
    (CVE-2020-1530)

  - A remote code execution vulnerability exists in the way
    that Microsoft Graphics Components handle objects in
    memory. An attacker who successfully exploited the
    vulnerability could execute arbitrary code on a target
    system.  (CVE-2020-1562)

  - A spoofing vulnerability exists when Windows incorrectly
    validates file signatures. An attacker who successfully
    exploited this vulnerability could bypass security
    features and load improperly signed files. In an attack
    scenario, an attacker could bypass security features
    intended to prevent improperly signed files from being
    loaded. The update addresses the vulnerability by
    correcting how Windows validates file signatures.
    (CVE-2020-1464)");
  # https://support.microsoft.com/en-us/help/4571736/windows-server-2012-update
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0551e21");
  # https://support.microsoft.com/en-us/help/4571702/windows-server-2012-update
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ece3db7");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4571702 or Cumulative Update KB4571736.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1564");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-1472");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Spooler Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS20-08';
kbs = make_list(
  '4571736',
  '4571702'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'6.2', 
                   sp:0,
                   rollup_date:'08_2020',
                   bulletin:bulletin,
                   rollup_kb_list:[4571736, 4571702])
)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}




