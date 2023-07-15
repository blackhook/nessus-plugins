#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(145244);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-11022", "CVE-2020-11023");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle WebCenter Sites (Jan 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"Oracle WebCenter Sites component of Oracle Fusion Middleware is affected by a vulnerability in the jQuery component.
Passing HTML from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e.
.html(), .append(), and others) may execute untrusted code.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2021.html#AppendixFMW");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2021cvrf.xml");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11022");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:webcenter_sites");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_webcenter_sites_installed.nbin", "oracle_enum_products_win.nbin");
  script_require_keys("SMB/WebCenter_Sites/Installed");

  exit(0);
}
include('vcf_extras_oracle_webcenter_sites.inc');

var app_info = vcf::oracle_webcenter_sites::get_app_info();

var constraints = [
  {'min_version' : '12.2.1.3', 'fixed_version' : '12.2.1.3.210119', 'fixed_revision' : '186084'},
  {'min_version' : '12.2.1.4', 'fixed_version' : '12.2.1.4.210119', 'fixed_revision' : '186094'}
];

vcf::oracle_webcenter_sites::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

