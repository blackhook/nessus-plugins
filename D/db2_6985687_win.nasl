#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175136);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/08");

  script_cve_id("CVE-2023-29255");
  script_xref(name:"IAVB", value:"2023-B-0028");

  script_name(english:"IBM DB2 10.5.0.11 FP 11 41270 / 11.1.4.7 FP 7 41268 / 11.5.7.0 FP 0 29113 / 11.5.8.0 FP 0 29133 DoS (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to it self-reported version number, IBM Db2 is vulnerable to a denial of service as it may trap when 
compiling a variation of an anonymous block.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6985687");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate IBM DB2 Fix Pack or Special Build based on the most recent fix pack level for your branch.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29255");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_and_db2_connect_installed.nbin");
  script_require_keys("SMB/db2/Installed");

  exit(0);
}

include('vcf_extras_db2.inc');

get_kb_item_or_exit('SMB/db2/Installed');
var app_info = vcf::ibm_db2::get_app_info();

var constraints = [
  {'equal':'10.5.0.11', 'fixed_build':'41270'},
  {'min_version':'10.5', 'fixed_version':'10.5.0.11', 'fixed_display':'10.5.0.11 + Special Build 41270'},
  {'equal':'11.1.4.7', 'fixed_build':'41268'},
  {'min_version':'11.1', 'fixed_version':'11.1.4.7', 'fixed_display':'11.1.4.7 + Special Build 41268'},
  {'equal':'11.5.7.0', 'fixed_build':'29113', 'fixed_display':'11.5.7.0 Special Build 29113'},
  {'equal':'11.5.8.0', 'fixed_build':'29133', 'fixed_display':'11.5.8.0 Special Build 29133'},
  {'min_version':'11.1', 'fixed_version':'11.5.7.0', 'fixed_display':'11.5.7.0 Special Build 29113'},
  {'min_version':'11.5.8.0', 'fixed_version':'11.5.8.0', 'fixed_display':'11.5.8.0 Special Build 29133'}
];

vcf::ibm_db2::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

