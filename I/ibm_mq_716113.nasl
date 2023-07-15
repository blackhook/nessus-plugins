##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144859);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-1551");

  script_name(english:"IBM MQ 8.0.0.2 < 8.0.0.9 / 9.0.0.0 < 9.0.0.4 (716113)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM MQ Server running on the remote host is affected by a vulnerability. IBM WebSphere MQ 8.0.0.2
through 8.0.0.8 and 9.0.0.0 through 9.0.0.3 could allow users to have more authority than they should have if an MQ
administrator creates an invalid user group name. IBM X-Force ID: 142888.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/716113");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM MQ 8.0.0.9, 9.0.0.4 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1551");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/12");

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

if (app_info['Type'] != 'Server')
  audit(AUDIT_HOST_NOT, 'an affected product');

constraints = [
  { 'min_version' : '8.0.0.2', 'max_version' : '8.0.0.8', 'fixed_version' : '8.0.0.9'},
  { 'min_version' : '9.0', 'max_version': '9.0.0.3', 'fixed_version' : '9.0.0.4'}
];


vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
