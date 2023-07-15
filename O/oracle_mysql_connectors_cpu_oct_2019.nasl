#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129974);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-1543", "CVE-2019-2920");
  script_bugtraq_id(107349);

  script_name(english:"Oracle MySQL Connectors Multiple Vulnerabilities (Oct 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle MySQL Connectors installed on the remote host is 8.0.x prior to 8.0.18 or 5.3.x prior to 5.3.14.
It is, therefore, affected by the following vulnerabilities as noted in the October 2019 Critical Patch Update
advisory:

  - An unspecified, remote security vulnerability in the Connector/ODBC component of Oracle MySQL Connectors.
    (CVE-2019-2920)

  - A vulnerability in the OpenSSL subcomponent of the Connector/ODBC component of Oracle MySQL Connectors caused by the
    ability to set variable nonce lengths in the ChaCha20-Poly1305 AEAD cipher. This could allow an unauthenticated,
    remote attacker to affect data confidentiality and integrity. (CVE-2019-1543)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b5081c3");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patches according to the October 2019 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1543");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_connectors");
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
    {'min_version': '5.3.0', 'fixed_version': '5.3.14'},
    {'min_version': '8.0.0', 'fixed_version': '8.0.18'}
  ];
else
  audit(AUDIT_PACKAGE_NOT_AFFECTED, product);

vcf::check_version_and_report(app_info: app_info, constraints: constraints, severity: SECURITY_WARNING);
