#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171142);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/22");

  script_cve_id("CVE-2022-42436");
  script_xref(name:"IAVA", value:"2023-A-0067");

  script_name(english:"IBM MQ Information Disclosure (6909467)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM MQ Server running on the remote host is affected by a vulnerability as referenced in the 6909467
advisory.

  - IBM MQ Managed File Transfer could allow a local user to obtain sensitive information from diagnostic files. 
    (CVE-2022-42436)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6909467");
  script_set_attribute(attribute:"see_also", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/238206");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 9.0.0.14 LTS, 9.1.0.13 LTS, 9.2.0.7 LTS, 9.3.0.2 LTS, 9.3.1.1 CD or later. Alternatively, install APAR IT42204 where
appropriate.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42436");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:mq");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

if (app_info['Type'] != 'Server')
  audit(AUDIT_HOST_NOT, 'an affected product');

var constraints;
# check if CD - less than 4 version segments or non-0 3rd (M) segment
# https://www.ibm.com/support/pages/ibm-mq-faq-long-term-support-and-continuous-delivery-releases
if (app_info['version'] =~ "^9\.([0-9]+\.?){0,2}$" || app_info['version'] =~ "^9\.[0-9]\.[1-9]")
{
  constraints = [
    { 'min_version' : '9.1', 'fixed_version' : '9.3.1.1' }
  ];
}
else
{
  # Some versions require an interim fix, which we are not checking, so require paranoia for those versions only
  if ((app_info['version'] =~ "^8.0.0.16") && report_paranoia < 2)
    audit(AUDIT_POTENTIAL_VULN, app, app_info['version']);
  constraints = [
    { 'min_version' : '8.0', 'max_version' : '8.0.0.16', 'fixed_display' : 'APAR IT42204' },
    { 'min_version' : '9.0', 'fixed_version' : '9.0.0.14' },
    { 'min_version' : '9.1', 'fixed_version' : '9.1.0.13' },
    { 'min_version' : '9.2', 'fixed_version' : '9.2.0.7' },
    { 'min_version' : '9.3', 'fixed_version' : '9.3.0.2' }
  ];
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);