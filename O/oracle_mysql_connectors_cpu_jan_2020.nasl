#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132937);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/21");

  script_cve_id("CVE-2019-1547");
  script_xref(name:"IAVA", value:"2020-A-0021-S");

  script_name(english:"Oracle MySQL Connectors OpenSSL (Jan 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle MySQL Connectors installed on the remote host is 8.0.x prior to 8.0.19 or 5.3.x prior to 5.3.14.
It is, therefore, affected by a vulnerability in OpenSSL as noted in the January 2020 Critical Patch Update advisory.
This vulnerability is due to a susceptibility to side-channel attacks in the OpenSSL implementation which allows a
local, unauthenticated attacker to fully recover a secret key during an ECDSA signature operation, provided the attacker
can time the creation of a large number of signatures.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2020.html#AppendixMSQL");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2622869.1");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patches according to the January 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1547");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_connectors");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_connectors_version_nix.nbin", "mysql_connectors_version_win.nbin");
  script_require_keys("installed_sw/MySQL Connector");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'MySQL Connector');
product = tolower(app_info['Product']);

vcf::check_granularity(app_info:app_info, sig_segments:3);

if ('odbc' >< product)
  constraints = [
    {'min_version': '5.3.0', 'fixed_version': '5.3.14'},
    {'min_version': '8.0.0', 'fixed_version': '8.0.19'}
  ];
else
  audit(AUDIT_PACKAGE_NOT_AFFECTED, product);

vcf::check_version_and_report(app_info: app_info, constraints: constraints, severity: SECURITY_NOTE);
