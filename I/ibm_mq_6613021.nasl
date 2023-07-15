#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164379);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/23");

  script_cve_id("CVE-2022-22489");
  script_xref(name:"IAVA", value:"2022-A-0337-S");

  script_name(english:"IBM MQ XXE (6613021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an XML external entity injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM MQ Server running on the remote host is affected by a vulnerability as referenced in the 6613021
advisory.

  - IBM MQ Explorer is vulnerable to an XML External Entity Injection (XXE) attack due to improper XML validation in
    the import Wizard. (CVE-2022-22489)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6613021");
  script_set_attribute(attribute:"see_also", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/226339");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 9.0.0.13, 9.1.0.11 LTS, 9.2.0.5 LTS, 9.3 CD or later. Alternatively, install APAR IT39183 where
appropriate.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22489");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:mq");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_mq_nix_installed.nbin", "websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ");

  exit(0);
}

include('vcf.inc');

var app = 'IBM WebSphere MQ';

var app_info = vcf::get_app_info(app:app);
var comps = tolower(app_info['Components']);

if (app_info['Type'] != 'Server')
  audit(AUDIT_HOST_NOT, 'an affected product');

if (comps !~ 'explorer')
  audit(AUDIT_NOT_INST, 'MQ Explorer component');

var constraints;
# check if CD - less than 4 version segments or non-0 3rd (M) segment
# https://www.ibm.com/support/pages/ibm-mq-faq-long-term-support-and-continuous-delivery-releases
if (app_info['version'] =~ "^9\.([0-9]+\.?){0,2}$" || app_info['version'] =~ "^9\.[0-9]\.[1-9]")
{
  constraints = [
    { 'min_version' : '9.1', 'fixed_version' : '9.3' }
  ];
}
else
{
  # Some versions require an interim fix, which we are not checking, so require paranoia for those versions only
  if ((app_info['version'] =~ "^8.0.0.16") && report_paranoia < 2)
    audit(AUDIT_POTENTIAL_VULN, app, app_info['version']);
  constraints = [
    { 'min_version' : '8.0', 'max_version' : '8.0.0.16', 'fixed_display' : 'APAR IT39183' },
    { 'min_version' : '9.0', 'fixed_version' : '9.0.0.13' },
    { 'min_version' : '9.1', 'fixed_version' : '9.1.0.11' },
    { 'min_version' : '9.2', 'fixed_version' : '9.2.0.5' }
  ];
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
