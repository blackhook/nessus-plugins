##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145054);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/20");

  script_cve_id("CVE-2018-1974");

  script_name(english:"IBM MQ 8.0 <= 8.0.0.10 / 9.0 <= 9.0.0.5 LTS / 9.1 <= 9.1.0.1 LTS / 9.1 <= 9.1.1 CD (792043)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM MQ Server running on the remote host is affected by a vulnerability. IBM WebSphere 8.0.0.0 through
9.1.1 could allow an authenticated attacker to escalate their privileges when using multiplexed channels. IBM X-Force
ID: 153915.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/792043");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM MQ 8.0.0.11 or later. Alternatively, install iFix IT24586 where appropriate.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1974");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_mq_nix_installed.nbin", "websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'IBM WebSphere MQ');

# Not checking for interim fix, so require paranoia for these versions only
if ((app_info['version'] =~ "^9.0" || app_info['version'] =~ "^9.1") && report_paranoia < 2)
  audit(AUDIT_PARANOID);

if (app_info['Type'] != 'Server')
  audit(AUDIT_HOST_NOT, 'an affected product');

# check if CD - less than 4 version segments or non-0 3rd (M) segment
# https://www.ibm.com/support/pages/ibm-mq-faq-long-term-support-and-continuous-delivery-releases
# We see CD on lab host NPW - IBM WebSphere MQ 9.0 is detected as: 9.0.3.0
if (app_info['version'] =~ "^9\.([0-9]+\.?){0,2}$" || app_info['version'] =~ "^9\.[0-9]\.[1-9]")
{
  constraints = [
    { 'min_version' : '9.1', 'max_version' : '9.1.1', 'fixed_display' : 'iFix IT24586'}
  ];
}
else
{
  constraints = [
    { 'min_version' : '8.0', 'max_version' : '8.0.0.10', 'fixed_version' : '8.0.0.11'},
    { 'min_version' : '9.0', 'max_version' : '9.0.0.5', 'fixed_display' : 'iFix IT24586'},
    { 'min_version' : '9.1', 'max_version' : '9.1.0.1', 'fixed_display' : 'iFix IT24586'}
  ];
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
