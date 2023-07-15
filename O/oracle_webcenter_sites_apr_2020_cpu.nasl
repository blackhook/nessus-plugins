#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135676);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-11358", "CVE-2019-16943", "CVE-2020-2739");
  script_xref(name:"IAVA", value:"2020-A-0153");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle WebCenter Sites Multiple Vulnerabilities (April 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by multiple security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Oracle WebCenter Sites component of Oracle Fusion Middleware is vulnerable to multiple vulnerabilities.

  - Component: Advanced UI (jQuery). The supported version that is affected is 12.2.1.3.0. 
  Easily exploitable vulnerability allows unauthenticated attacker with network access via 
  HTTP to compromise Oracle WebCenter Sites. Successful attacks require human interaction 
  from a person other than the attacker and while the vulnerability is in Oracle WebCenter 
  Sites, attacks may significantly impact additional products. Successful attacks of this 
  vulnerability can result in unauthorized update, insert or delete access to some of 
  Oracle WebCenter Sites accessible data as well as unauthorized read access to a subset 
  of Oracle WebCenter Sites accessible data (CVE-2019-11358).

  - Component: Sites (jackson-databind). Supported versions that are affected are 
  12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated 
  attacker with network access via HTTP to compromise Oracle WebCenter Sites. 
  Successful attacks of this vulnerability can result in takeover of Oracle WebCenter Sites
  (CVE-2019-16943).

  - Component: Advanced UI. The supported version that is affected is 12.2.1.3.0. 
  Easily exploitable vulnerability allows unauthenticated attacker with network access 
  via HTTP to compromise Oracle WebCenter Sites. Successful attacks require human interaction 
  from a person other than the attacker and while the vulnerability is in Oracle WebCenter Sites, 
  attacks may significantly impact additional products. Successful attacks of this vulnerability 
  can result in unauthorized access to critical data or complete access to all Oracle 
  WebCenter Sites accessible data (CVE-2020-2739).");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2020 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16943");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_webcenter_sites_installed.nbin", "oracle_enum_products_win.nbin");
  script_require_keys("SMB/WebCenter_Sites/Installed");

  exit(0);
}
include('vcf_extras_oracle_webcenter_sites.inc');

var app_info = vcf::oracle_webcenter_sites::get_app_info();

# vulnerable versions: 
# - 12.2.1.3.0 - Revision 185862, Patch 29957990
#     Note that the revision does not match up with the version suffix shown in the readme
#
# - 12.2.1.4.0 - Patch 31101341
#     This patch does not change revision. Need to find specific patch

var constraints = [
  {'min_version' : '12.2.1.3', 'fixed_version' : '12.2.1.3.190715', 'fixed_revision' : '185862'},
  {'min_version' : '12.2.1.4', 'fixed_version' : '12.2.1.4.200415'}
];

vcf::oracle_webcenter_sites::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
