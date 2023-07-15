#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169978);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/13");

  script_cve_id("CVE-2019-11358");
  script_xref(name:"IAVA", value:"2019-A-0384");
  script_xref(name:"IAVA", value:"2020-A-0150");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Enterprise Manager Ops Center UI or Other Patch (Oct 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise management application installed on the remote host is
affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager Ops Center installed on the remote host is affected by a vulnerability as
described in the October 2019 Critical Patch Update (CPU). Vulnerability in the Enterprise Manager Ops Center product
of Oracle Enterprise Manager (component: Networking (jQuery)). Supported versions that are affected are 12.3.3 and
12.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
Enterprise Manager Ops Center. Successful attacks require human interaction from a person other than the attacker and
while the vulnerability is in Enterprise Manager Ops Center, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of
Enterprise Manager Ops Center accessible data as well as unauthorized read access to a subset of Enterprise Manager
Ops Center accessible data.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/security-alerts/cpuoct2019.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c94f8e4");
  # https://www.oracle.com/security-alerts/cpuoct2019verbose.html#EM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17ac9b74");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2019
Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11358");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager_ops_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_ops_center_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Ops Center");

  exit(0);
}

include('vcf_extras_oracle_em_ops_center.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

var constraints = [
  {'min_version': '12.3.3.0', 'max_version': '12.3.3.9999', 'ui_patch': '30295446'},
  {'min_version': '12.4.0.0', 'max_version': '12.4.0.9999', 'ui_patch': '30295450'}
];

var app_info = vcf::oracle_em_ops_center::get_app_info();

vcf::oracle_em_ops_center::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
