#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151457);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/05");

  script_cve_id("CVE-2021-20579", "CVE-2021-29777");

  script_name(english:"IBM DB2 9.7 < 9.7 / 10.1 < 10.1 / 10.5 < 10.5 / 11.1 < 11.1.4 / 11.5 < 11.5.6 Multiple Vulnerabilities (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, IBM Db2 is affected by multiple vulnerabilities:

  - IBM Db2 for Linux, UNIX and Windows could allow an unauthenticated attacker to cause a denial of service due to a
    specific circumstance of a table being dropped while being accessed in another session. (CVE-2021-29777)

  - IBM Db2 db2fm is vulnerable to an information disclosure as it could allow a user who can create a view or inline 
    SQL function to obtain sensitive information when AUTO_REVAL is set to DEFFERED_FORCE. (CVE-2021-20579)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6466369");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6466373");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate IBM DB2 Fix Pack or Special Build based on the most recent fix pack level for your branch.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20579");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_and_db2_connect_installed.nbin");
  script_require_keys("SMB/db2/Installed");

  exit(0);
}

include('vcf_extras_db2.inc');

get_kb_item_or_exit('SMB/db2/Installed');
var app_info = vcf::ibm_db2::get_app_info();

var constraints = [
  {'equal':'9.7.1100.352', 'fixed_build':'40801'},
  {'equal':'10.1.600.580', 'fixed_build':'40800'},
  {'equal':'10.5.1100.2866', 'fixed_build':'40802'},
  {'equal':'11.1.4060.1324', 'fixed_build':'40812'},
  {'min_version':'9.7', 'fixed_version':'9.7.1100.352', 'fixed_display':'9.7.1100.352 + Special Build 40801'},
  {'min_version':'10.1', 'fixed_version':'10.1.600.580', 'fixed_display':'10.1.600.580 + Special Build 40800'},
  {'min_version':'10.5', 'fixed_version':'10.5.1100.2866', 'fixed_display':'10.5.1100.2866 + Special Build 40802'},
  {'min_version':'11.1', 'fixed_version':'11.1.4060.1324', 'fixed_display':'11.1.4060.1324 + Special Build 40812'},
  {'min_version':'11.5', 'fixed_version':'11.5.6000.1809'}
];

vcf::ibm_db2::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);

