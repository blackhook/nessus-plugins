##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164042);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2022-35742");
  script_xref(name:"IAVA", value:"2022-A-0316-S");
  script_xref(name:"IAVA", value:"2022-A-0325-S");

  script_name(english:"Security Updates for Outlook C2R DoS (August 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Outlook application installed on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Outlook application installed on the remote host is missing a security update. It is, therefore,
affected by a denial of service (DoS) vulnerability. An attacker can exploit this issue to cause the affected
component to deny system or application services.
    
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5001990");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002051");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and
manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-35742");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS22-08';

var constraints = [
  {'fixed_version':'16.0.15427.20210','channel':'2016 Retail'},
  {'fixed_version':'16.0.15427.20210','channel':'Current'},
  {'fixed_version':'16.0.15330.20298','channel':'Enterprise Deferred','channel_version':'2206'},
  {'fixed_version':'16.0.15225.20394','channel':'Enterprise Deferred'},
  {'fixed_version':'16.0.14931.20660','channel':'First Release for Deferred'},
  {'fixed_version':'16.0.14931.20660','channel':'Deferred','channel_version':'2202'},
  {'fixed_version':'16.0.14326.21096','channel':'Deferred','channel_version':'2108'},
  {'fixed_version':'16.0.13801.21582','channel':'Deferred'},
  {'fixed_version':'16.0.12527.22197','channel':'Microsoft 365 Apps on Windows 7'},
  {'fixed_version':'16.0.15427.20210','channel':'2021 Retail'},
  {'fixed_version':'16.0.15427.20210','channel':'2019 Retail'},
  {'fixed_version':'16.0.14332.20358','channel':'LTSC 2021'},
  {'fixed_version':'16.0.10389.20033','channel':'2019 Volume'}
];

vcf::microsoft::office_product::check_version_and_report(
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Outlook'
);

