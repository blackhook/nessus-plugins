#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(142146);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-11022");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle JDeveloper XSS (October 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JDeveloper installed on the remote host is missing a security patch. It is, therefore, affected 
by a cross-site scripting (XSS) vulnerability in the ADF Faces (jQuery) component. An unauthenticated, remote attacker
can exploit this issue to compromise Oracle JDeveloper. Successful attacks require human interaction from a person other
than the attacker and while the vulnerability is in Oracle JDeveloper, attacks may significantly impact additional
products. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of
Oracle JDeveloper accessible data as well as unauthorized read access to a subset of Oracle JDeveloper accessible data.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2020.html");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-gxr4-xjj5-5px2");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11022");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdeveloper");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_jdeveloper_installed.nbin");
  script_require_keys("installed_sw/Oracle JDeveloper");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_jdev::get_app_info();

var constraints = [
  { 'min_version':'11.1.1.9', 'fixed_version':'11.1.1.9.201020', 'missing_patch':'31985571' },
  { 'min_version':'12.2.1.3', 'fixed_version':'12.2.1.3.201007', 'missing_patch':'31985811' },
  { 'min_version':'12.2.1.4', 'fixed_version':'12.2.1.4.200817', 'missing_patch':'31762739' }
];

vcf::oracle_jdev::check_version_and_report(
  app_info:app_info,
  severity:SECURITY_WARNING,
  constraints:constraints,
  flags:{'xss':TRUE}
);
