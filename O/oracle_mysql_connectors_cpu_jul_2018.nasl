#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129004);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-0739");
  script_bugtraq_id(103518);
  script_xref(name:"IAVA", value:"2018-A-0229-S");

  script_name(english:"Oracle MySQL Connectors DoS (Jul 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a Denial of Service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle MySQL Connectors installed on the remote host is 8.0.x prior to 8.0.12 or 5.3.x prior to 5.3.11.
It is, therefore, affected by a denial of service vulnerability as noted in the July 2018 Critical Patch Update
advisory. This vulnerability is related to OpenSSL's handling of recursive ASN.1 structures: given specially crafted
input with excessive recursion, an attacker can cause a stack overflow that results in a denial of service.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5103b2d3");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patches according to the July 2018 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0739");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_connectors");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_connectors_version_nix.nbin", "mysql_connectors_version_win.nbin");
  script_require_keys("installed_sw/MySQL Connector");

  exit(0);
}

include('vcf.inc');

appname = 'MySQL Connector';

app_info = vcf::get_app_info(app:appname);
product = tolower(app_info['Product']);

vcf::check_granularity(app_info:app_info, sig_segments:3);

if ('odbc' >< product)
  constraints = [
    {'min_version': '5.3.0', 'fixed_version': '5.3.11'},
    {'min_version': '8.0.0', 'fixed_version': '8.0.12'}
  ];
else
  audit(AUDIT_PACKAGE_NOT_AFFECTED, product);

vcf::check_version_and_report(app_info: app_info, constraints: constraints, severity: SECURITY_WARNING);
