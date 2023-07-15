#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158039);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/02");

  script_cve_id("CVE-2022-23276");
  script_xref(name:"IAVA", value:"2022-A-0076-S");
  script_xref(name:"MSKB", value:"5010657");
  script_xref(name:"MSKB", value:"5011376");
  script_xref(name:"MSFT", value:"MS22-5010657");
  script_xref(name:"MSFT", value:"MS22-5011376");

  script_name(english:"Security Updates for Microsoft SQL Server (February 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server installation on the remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server installation on the remote host is missing a security update. It is, therefore, affected by a
privilege escalation vulnerability that exists in Microsoft SQL Server 2019 Linux container images. An unauthenticated,
local attacker could exploit this to elevate privileges. This vulnerability is not present on servers that are running
SQL Server 2019 on Linux bare metal or VMs. This vulnerability is exposed only in SQL Server 2019 Linux container
images.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.microsoft.com/en-gb/topic/kb5010657-description-of-the-security-update-for-sql-server-2019-gdr-february-8-2022-49c03140-0495-4504-82cd-e920c2ea81bc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74d44583");
  # https://support.microsoft.com/en-us/topic/kb5011376-escalation-of-privileges-on-a-linux-vm-running-microsoft-sql-server-container-images-3df39293-ed0c-4410-a52f-59d195ced15d
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01dc8db7");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB5010657 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23276");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mssqlserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports(139, 445, 1433, "Services/mssql");

  exit(0);
}

include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::mssql::get_app_info();

var constraints =
[
  {
    'sql_server'    : '2014',
    'arch'          : 'x64',
    'file'          : 'sqlservr.exe',
    'min_version'   : '15.0.0.0',
    'fixed_version' : '15.0.2090.38',
    'kb'            : '5010657, 5011376'
  },
];

vcf::microsoft::mssql::check_version_and_report(
  app_info          : app_info,
  constraints       : constraints,
  severity          : SECURITY_WARNING
);