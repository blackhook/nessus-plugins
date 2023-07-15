#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152525);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id("CVE-2021-34524", "CVE-2021-36946", "CVE-2021-36950");
  script_xref(name:"MSKB", value:"4618809");
  script_xref(name:"MSKB", value:"4618795");
  script_xref(name:"MSKB", value:"5005239");
  script_xref(name:"MSFT", value:"MS21-4618809");
  script_xref(name:"MSFT", value:"MS21-4618795");
  script_xref(name:"MSFT", value:"MS21-5005239");
  script_xref(name:"IAVA", value:"2021-A-0375-S");

  script_name(english:"Security Updates for Microsoft Dynamics 365 (on-premises) (August 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 (on-premises) is affected by an cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 (on-premises) installation on the remote host is missing security updates. It is, therefore,
affected by multiple vulnerabilities: 

  - Remote Code Execution Vulnerability (CVE-2021-34524)

  - Cross-site Scripting Vulnerabilities (CVE-2021-36946, CVE-2021-36950)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version   
number.");
  # https://support.microsoft.com/en-us/topic/service-update-0-30-for-microsoft-dynamics-365-9-0-10641bb0-ebfe-477e-858a-ea4ab42a0476
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f91bb548");
  # https://support.microsoft.com/en-us/topic/service-update-0-31-for-microsoft-dynamics-crm-on-premises-9-0-5bb7ff5b-8fbd-465c-8590-6e4522289913
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f4aaa913");
  # https://support.microsoft.com/en-us/topic/service-update-1-3-for-microsoft-dynamics-crm-on-premises-9-1-4f9cb846-6c00-4fc1-9c13-bc0bbe733009
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92ef4b15");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4618809
  -KB4618795
  -KB5005239");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34524");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '9.0', 'fixed_version' : '9.0.31.7' },
  { 'min_version' : '9.1', 'fixed_version' : '9.1.3.11' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
