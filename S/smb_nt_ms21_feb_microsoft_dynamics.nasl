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
  script_id(146331);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id("CVE-2021-24101");
  script_xref(name:"MSKB", value:"4595460");
  script_xref(name:"MSKB", value:"4595463");
  script_xref(name:"MSFT", value:"MS21-4595460");
  script_xref(name:"MSFT", value:"MS21-4595463");
  script_xref(name:"IAVA", value:"2021-A-0081-S");

  script_name(english:"Security Updates for Microsoft Dynamics 365 (on-premises) (February 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 (on-premises) is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 (on-premises) is missing security updates. It is, therefore, affected by an information
disclosure vulnerability in Microsoft Dataverse. An authenticated, remote attacker could exploit this to obtain data
stored in the underlying datasets in Dataverse, that could include Personal Identifiable Information.");
  # https://support.microsoft.com/en-us/topic/service-update-0-24-for-microsoft-dynamics-365-9-0-61169f11-12c0-6b56-178d-2b75f8ace1d7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?49cc0186");
  # https://support.microsoft.com/en-us/topic/microsoft-dynamics-365-on-premises-update-2-26-c5b3a792-a8d0-f5d2-107f-4b2f22c97512
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa7d12b1");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4595460
  -KB4595463");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-24101");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_365_detect.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics 365 Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

app = 'Microsoft Dynamics 365 Server';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '8.0', 'fixed_version' : '8.2.26.14' },
  { 'min_version' : '9.0', 'fixed_version' : '9.0.24.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
