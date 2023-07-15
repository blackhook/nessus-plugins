##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163944);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2022-35742");
  script_xref(name:"MSKB", value:"5001990");
  script_xref(name:"MSKB", value:"5002051");
  script_xref(name:"MSFT", value:"MS22-5001990");
  script_xref(name:"MSFT", value:"MS22-5002051");
  script_xref(name:"IAVA", value:"2022-A-0316-S");
  script_xref(name:"IAVA", value:"2022-A-0325-S");

  script_name(english:"Security Updates for Outlook (August 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Outlook application installed on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Outlook application installed on the remote host is missing a security update. It is, therefore, affected
by the following vulnerability:

  - A denial of service (DoS) vulnerability. An attacker can exploit this issue to cause the affected
    component to deny system or application services. (CVE-2022-35742)
    
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5001990");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002051");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5001990
  -KB5002051

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-35742");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS22-08';
var kbs = make_list(
  '5001990',
  '5002051'
);

var constraints = [
  { 'kb':'5001990',  'fixed_version': '15.0.5399.1000', 'sp' : 1},
  { 'kb':'5002051', 'channel':'MSI', 'fixed_version': '16.0.5257.1000', 'sp' : 0}
];

vcf::microsoft::office_product::check_version_and_report(
  kbs:kbs,
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Outlook'
);
