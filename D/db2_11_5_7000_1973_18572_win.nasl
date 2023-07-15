##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163699);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/05");

  script_cve_id("CVE-2022-22389", "CVE-2022-22390");

  script_name(english:"IBM DB2 9.7 < 9.7 FP 11 41114 / 10.1 < 10.1 FP 6 41109 / 10.5 < 10.5 FP 11 41110 /  11.1 < 11.1.4 FP 7 41112 / 11.5 < 11.5.7 FP 0 18572 Multiple Vulnerabilities (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by an denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, IBM Db2 is affected by multiple vulnerabilities, as follows:

  - A denial of service (DOS) vulnerability as the server may terminate abnormally when executing specially
    crafted SQL statements by an authenticated user. (CVE-2022-22389)

  - An information disclosure caused by improper privilege management when table function is used.
    (CVE-2022-22390)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6598047");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6597993");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate IBM DB2 Fix Pack or Special Build based on the most recent fix pack level for your branch.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22390");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
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
  {'equal':'9.7.1100.352', 'fixed_build':'41114', 'fixed_display':'9.7.1100.352 Special Build 41114'},
  {'equal':'10.1.600.580', 'fixed_build':'41109', 'fixed_display':'10.1.600.580 Special Build 41109'},
  {'equal':'10.5.1100.2866', 'fixed_build':'41110', 'fixed_display':'10.5.1100.2866 Special Build 41110'},
  {'equal':'11.1.4070.1733', 'fixed_build':'41112', 'fixed_display':'11.1.4070.1733 Special Build 41112'},
  {'equal':'11.5.7000.1973', 'fixed_build':'18572', 'fixed_display':'11.5.7000.1973 Special Build 18572'},
  {'min_version':'9.7', 'fixed_version':'9.7.1100.352', 'fixed_display':'9.7.1100.352 Special Build 41114'},
  {'min_version':'10.1', 'fixed_version':'10.1.600.580', 'fixed_display':'10.1.600.580 Special Build 41109'},
  {'min_version':'10.5', 'fixed_version':'10.5.1100.2866', 'fixed_display':'10.5.1100.2866 Special Build 41110'},
  {'min_version':'11.1', 'fixed_version':'11.1.4070.1733', 'fixed_display':'11.1.4070.1733 Special Build 41112'},
  {'min_version':'11.5', 'fixed_version':'11.5.7000.1973', 'fixed_display':'11.5.7000.1973 Special Build 18572'}
];

vcf::ibm_db2::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

