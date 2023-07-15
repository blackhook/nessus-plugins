#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133041);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-0227");
  script_bugtraq_id(107867);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Tuxedo Remote Code Execution Vulnerability (Jan 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Tuxedo installed on the remote host is missing a security patch. It is, therefore, affected by 
a remote code execution vulnerability due to a Server Side Request Forgery (SSRF) vulnerability found in the Apache 
Axis 1.4 distribution used in the TX SALT component.");
  # https://www.oracle.com/security-alerts/cpujan2020.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?383db271");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0227");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:tuxedo");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_tuxedo_installed.nbin");
  script_require_keys("installed_sw/Oracle Tuxedo");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::get_app_info(app:'Oracle Tuxedo');

var constraints = [
  {'version_regex':"^12\.1\.1\.0($|\.|_)", 'rp_fix': 100},
  {'version_regex':"^12\.1\.3\.0($|\.|_)", 'rp_fix': 108}
];

vcf::oracle_tuxedo::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);