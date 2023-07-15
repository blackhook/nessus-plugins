#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157190);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/05");

  script_cve_id("CVE-2021-38931");
  script_xref(name:"IAVB", value:"2022-B-0001-S");

  script_name(english:"IBM DB2 11.1 < 11.1.4 FP 6 41025 / 11.5 < 11.5.7 Information Disclosure (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, IBM Db2 is affected by an information disclosure vulnerability as a
result of a connected user having indirect read access to a table where they are not authorized to select from.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6523810");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate IBM DB2 Fix Pack or Special Build based on the most recent fix pack level for your branch.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38931");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_and_db2_connect_installed.nbin");
  script_require_keys("SMB/db2/Installed");

  exit(0);
}

include('vcf_extras_db2.inc');

get_kb_item_or_exit('SMB/db2/Installed');
var app_info = vcf::ibm_db2::get_app_info();

var constraints = [
  {'equal':'11.1.4060.1324', 'fixed_build':'41025'},
  {'min_version':'11.1', 'fixed_version':'11.1.4060.1324', 'fixed_display':'11.1.4060.1324 + Special Build 41025'},
  {'min_version':'11.5', 'fixed_version':'11.5.7000.1973'}
];

vcf::ibm_db2::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

