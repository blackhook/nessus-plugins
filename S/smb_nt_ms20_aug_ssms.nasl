#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(139584);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-1455");
  script_xref(name:"IAVA", value:"2020-A-0357");
  script_xref(name:"CEA-ID", value:"CEA-2020-0101");

  script_name(english:"Security Updates for SQL Server Management Studio (August 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The SQL Server Management Studio installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The SQL Server Management Studio installation on the remote
host is missing a security update. It is, therefore,
affected by the following vulnerability :

  - A denial of service vulnerability exists when Microsoft
    SQL Server Management Studio (SSMS) improperly handles
    files. An attacker could exploit the vulnerability to
    trigger a denial of service.  (CVE-2020-1455)");
  script_set_attribute(attribute:"solution", value:
"Refer to Microsoft documentation and upgrade to relevant fixed version.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1455");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server_management_studio");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_ssms_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Microsoft SSMS");
  script_require_ports(139, 445);

  exit(0);
}


include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"Microsoft SSMS");

# 18.0 is 2019.150.18118.0
# 18.6 is 2019.150.18338.0
constraints = [
  { "min_version":"2019.150.18118.0", "fixed_version":"2019.150.18338.0", "fixed_display":"2019.150.18338.0 (18.6)"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);


