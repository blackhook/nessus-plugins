#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108811);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/05");

  script_cve_id(
    "CVE-2008-0015",
    "CVE-2008-0020",
    "CVE-2008-4038",
    "CVE-2008-4114",
    "CVE-2008-4250",
    "CVE-2008-4609",
    "CVE-2008-4835",
    "CVE-2009-0086",
    "CVE-2009-0089",
    "CVE-2009-0550",
    "CVE-2009-0901",
    "CVE-2009-1925",
    "CVE-2009-1926",
    "CVE-2009-1930",
    "CVE-2009-2493",
    "CVE-2009-2494",
    "CVE-2009-2505",
    "CVE-2009-3676",
    "CVE-2009-3677",
    "CVE-2009-3678",
    "CVE-2010-0020",
    "CVE-2010-0021",
    "CVE-2010-0022",
    "CVE-2010-0231",
    "CVE-2010-0239",
    "CVE-2010-0240",
    "CVE-2010-0241",
    "CVE-2010-0242",
    "CVE-2010-0269",
    "CVE-2010-0270",
    "CVE-2010-0476",
    "CVE-2010-0477",
    "CVE-2010-1263",
    "CVE-2010-2550",
    "CVE-2010-2551",
    "CVE-2010-2552"
  );
  script_bugtraq_id(
    31179,
    31545,
    31647,
    31874,
    33121,
    33122,
    34435,
    34437,
    34439,
    35558,
    35585,
    35828,
    35832,
    35982,
    35993,
    36265,
    36269,
    36989,
    37197,
    37198,
    38049,
    38051,
    38054,
    38061,
    38062,
    38063,
    38064,
    38085,
    39312,
    39336,
    39339,
    39340,
    40237,
    40574,
    42224,
    42263,
    42267
  );
  script_xref(name:"CERT", value:"827267");
  script_xref(name:"IAVA", value:"2008-A-0081-S");
  script_xref(name:"IAVA", value:"2009-A-0077-S");
  script_xref(name:"IAVA", value:"2009-A-0126-S");
  script_xref(name:"IAVA", value:"2010-A-0030-S");
  script_xref(name:"IAVB", value:"2009-B-0037-S");
  script_xref(name:"CERT", value:"180513");
  script_xref(name:"CERT", value:"456745");
  script_xref(name:"EDB-ID", value:"6463");
  script_xref(name:"EDB-ID", value:"6824");
  script_xref(name:"EDB-ID", value:"7104");
  script_xref(name:"EDB-ID", value:"7132");
  script_xref(name:"EDB-ID", value:"9108");
  script_xref(name:"EDB-ID", value:"16615");
  script_xref(name:"EDB-ID", value:"14607");
  script_xref(name:"MSFT", value:"MS08-063");
  script_xref(name:"MSFT", value:"MS08-067");
  script_xref(name:"MSFT", value:"MS09-001");
  script_xref(name:"MSFT", value:"MS09-013");
  script_xref(name:"MSFT", value:"MS09-037");
  script_xref(name:"MSFT", value:"MS09-042");
  script_xref(name:"MSFT", value:"MS09-048");
  script_xref(name:"MSFT", value:"MS09-071");
  script_xref(name:"MSFT", value:"MS10-009");
  script_xref(name:"MSFT", value:"MS10-012");
  script_xref(name:"MSFT", value:"MS10-020");
  script_xref(name:"MSFT", value:"MS10-043");
  script_xref(name:"MSFT", value:"MS10-054");
  script_xref(name:"MSFT", value:"MS10-083");
  script_xref(name:"MSKB", value:"957095");
  script_xref(name:"MSKB", value:"958644");
  script_xref(name:"MSKB", value:"958687");
  script_xref(name:"MSKB", value:"960803");
  script_xref(name:"MSKB", value:"967723");
  script_xref(name:"MSKB", value:"960859");
  script_xref(name:"MSKB", value:"973354");
  script_xref(name:"MSKB", value:"973507");
  script_xref(name:"MSKB", value:"973540");
  script_xref(name:"MSKB", value:"973815");
  script_xref(name:"MSKB", value:"973869");
  script_xref(name:"MSKB", value:"974318");
  script_xref(name:"MSKB", value:"971468");
  script_xref(name:"MSKB", value:"974145");
  script_xref(name:"MSKB", value:"980232");
  script_xref(name:"MSKB", value:"979687");
  script_xref(name:"MSKB", value:"982214");
  script_xref(name:"MSKB", value:"2032276");

  script_name(english:"Windows Server 2008 Critical RCE Vulnerabilities (uncredentialed) (PCI/DSS)");
  script_summary(english:"Checks the OS version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote host may allow remote code execution.");
  script_set_attribute(attribute:"description", value:
"According to the version number obtained by NTLM the
remote host has Windows Server 2008 installed. The host
may be vulnerable to a number of vulnerabilities including
remote unauthenticated code execution.");
  script_set_attribute(attribute:"solution", value:
"Ensure the appropriate patches have been applied.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:X/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-4038");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft DirectShow (msvidctl.dll) MPEG-2 Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(16, 20, 94, 119, 189, 255, 264, 287, 310, 362, 399);

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smtp_ntlm_info.nasl");
  script_require_keys("Settings/ParanoidReport", "Settings/PCI_DSS");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");
include("audit.inc");

if (!get_kb_item("Settings/PCI_DSS"))
{
  audit(AUDIT_PCI);
}

if (report_paranoia < 2)
{
  audit(AUDIT_PARANOID);
}

port = get_kb_item_or_exit("Services/smtp");
os_version = get_kb_item_or_exit("smtp/"+port+"/ntlm/host/os_version");
if (os_version != "6.0.6001")
{
  audit(AUDIT_OS_SP_NOT_VULN);
}

security_report_v4(severity:SECURITY_HOLE, port:port);
exit(0);
