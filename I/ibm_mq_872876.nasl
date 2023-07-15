##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145057);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/05");

  script_cve_id("CVE-2019-4078");

  script_name(english:"IBM MQ 8.0 <= 8.0.0.11 / 9.0 <= 9.0.0.5 LTS / 9.1 <= 9.1.0.1 LTS / 9.1.1 < 9.1.2 CD (872876)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM MQ Server running on the remote host is affected by a vulnerability that allows a local
non-privileged user to execute code as an administrator due to incorrect permissions set on MQ installation directories.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/872876");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM MQ 8.0.0.12, 9.0.0.6, 9.1.0.2, 9.1.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-4078");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_mq_nix_installed.nbin", "websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'IBM WebSphere MQ');

if (app_info['Type'] != 'Server')
  audit(AUDIT_HOST_NOT, 'an affected product');

# check if CD - less than 4 version segments or non-0 3rd (M) segment
# https://www.ibm.com/support/pages/ibm-mq-faq-long-term-support-and-continuous-delivery-releases
# We see CD on lab host is detected as: 9.0.3.0
if (app_info['version'] =~ "^9\.([0-9]+\.?){0,2}$" || app_info['version'] =~ "^9\.[0-9]\.[1-9]")
{
  constraints = [
    { 'min_version' : '9.1.1', 'fixed_version' : '9.1.2'}
  ];
}
else
{
  constraints = [
    { 'min_version' : '8.0', 'max_version': '8.0.0.11',  'fixed_version' : '8.0.0.12'},
    { 'min_version' : '9.0', 'max_version': '9.0.0.5',  'fixed_version' : '9.0.0.6'},
    { 'min_version' : '9.1', 'max_version': '9.1.0.1',  'fixed_version' : '9.1.0.2'}
  ];
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
