#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were extracted from the Microsoft Security Updates 
# API. The text itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(140534);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-1044");
  script_xref(name:"IAVA", value:"2020-A-0410-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0118");

  script_name(english:"Security Updates for Microsoft SQL Server Reporting Services (September 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server Reporting Services installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server Reporting Services installation on the remote host is missing a security update. It is,
therefore, affected by a security feature bypass vulnerability in SQL Server Reporting Services (SSRS) due to improper 
validation of uploaded attachments to reports. An authenticated, remote attacker could exploit this issue to upload file 
types that were disallowed by an administrator. (CVE-2020-1044)");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1044
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5708b76b");
  script_set_attribute(attribute:"solution", value:
"Refer to Microsoft documentation and upgrade to relevant fixed version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1044");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server_reporting_services");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sql_server_reporting_services_installed.nbin");
  script_require_keys("installed_sw/Microsoft SQL Server Reporting Services");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Microsoft SQL Server Reporting Services', win_local:TRUE);

constraints = [
  { 'min_version':'14.0.0.0', 'fixed_version' : '14.0.600.1669'},
  { 'min_version':'15.0.0.0', 'fixed_version' : '15.0.7545.4810'}
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);


