#%NASL_MIN_LEVEL 80900
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
  script_id(175441);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/15");

  script_cve_id("CVE-2023-23375", "CVE-2023-28304");
  script_xref(name:"IAVA", value:"2023-A-0189");

  script_name(english:"Security Updates for Microsoft SQL Server ODBC Driver (April 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server driver installation on the remote host is
missing a security update. It is, therefore, affected by the
following vulnerability:

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2023-28304)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28304");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23375");
  # https://learn.microsoft.com/en-us/sql/connect/oledb/release-notes-for-oledb-driver-for-sql-server?view=sql-server-ver16#previous-releases
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0746d221");
  # https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server?view=sql-server-ver16#version-17
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c041c1a");
  # https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server?view=sql-server-ver16#download-for-windows
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?189633f4");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for the Microsoft SQL Driver.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28304");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_odbc_driver_for_sql_server_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
include('install_func.inc');
include('smb_hotfixes_fcheck.inc');

var app = 'Microsoft ODBC Driver for SQL Server';

var app_info = vcf::get_app_info(app:app);

var constraints = [
  { 'min_version' : '17.0',  'fixed_version' : '17.10.3.1' },
  { 'min_version' : '18.0',  'fixed_version' : '18.2.1.1' },
  { 'min_version' : '18.6', 'fixed_version' : '18.6.5' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);

