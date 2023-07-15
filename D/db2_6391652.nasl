##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144811);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/07");

  script_cve_id("CVE-2020-4642");
  script_xref(name:"IAVB", value:"2021-B-0002-S");

  script_name(english:"IBM DB2 9.7 < 9.7.1100.352 / 10.5 < 10.5.1100.2866 / 11.1 < 11.1.4050.859 / 11.5 < 11.5.5000.1587 DoS (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"IBM DB2 for Windows (includes DB2 Connect Server) 9.7, 10.1, 10.5, 11.1, and 11.5 could allow a local
attacker to cause a denial of service inside the 'DB2 Management Service'.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6391652");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate IBM DB2 Fix Pack or Special Build based on the most recent fix pack level for your branch.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4642");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_and_db2_connect_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/DB2 Server");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'DB2 Server', win_local:TRUE);

constraints = [
  {'min_version': '9.7',  'fixed_version' : '9.7.1100.352'},
  {'min_version': '10.1', 'fixed_version' : '10.1.600.580'},
  {'min_version': '10.5', 'fixed_version' : '10.5.1100.2866'},
  {'min_version': '11.1', 'fixed_version' : '11.1.4050.859'},
  {'min_version': '11.5', 'fixed_version' : '11.5.5000.1587'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);