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
  script_id(153385);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id("CVE-2021-40440");
  script_xref(name:"MSKB", value:"5006075");
  script_xref(name:"MSKB", value:"5006076");
  script_xref(name:"MSFT", value:"MS21-5006075");
  script_xref(name:"MSFT", value:"MS21-5006076");
  script_xref(name:"IAVA", value:"2021-A-0427-S");

  script_name(english:"Security Updates for Microsoft Dynamics 365 (on-premises) (September 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 (on-premises) is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 (on-premises) is missing a
security update. It is, therefore, affected by the following
vulnerability:

  - A cross-site scripting (XSS) vulnerability exists due to
    improper validation of user-supplied input before
    returning it to users. An attacker can exploit this by
    convincing a user to click a specially crafted URL, to
    execute arbitrary script code in a user's browser
    session. (CVE-2021-40440)");
  # https://support.microsoft.com/en-us/topic/update-17-10-for-microsoft-dynamics-365-business-central-2020-release-wave-2-application-build-17-10-29463-platform-build-17-0-29460-september-14-2021-kb5006075-f24a085e-9dea-4ee5-a48d-87882107a19e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d76e3f35");
  # https://support.microsoft.com/en-us/topic/update-18-5-for-microsoft-dynamics-365-business-central-2021-release-wave-1-application-build-18-5-29545-platform-build-18-0-29486-september-14-2021-kb5006076-ed5b4986-6955-45b8-8037-ddedf3e5bff0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe9bcee0");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5006075
  -KB5006076");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40440");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_365_business_central_server_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics 365 Business Central Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

var app = 'Microsoft Dynamics 365 Business Central Server';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '17.0', 'fixed_version' : '17.0.29460.0', 'fixed_display' : 'Update 17.10 for Microsoft Dynamics 365 Business Central 2020 Release Wave 2' },
  { 'min_version' : '18.0', 'fixed_version' : '18.0.29486.0', 'fixed_display' : 'Update 18.5 for Microsoft Dynamics 365 Business Central 2021 Release Wave 1' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE,
  flags:{'xss':TRUE}
);
