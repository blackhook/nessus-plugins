##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146085);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/05");

  script_cve_id("CVE-2020-4682");
  script_xref(name:"IAVA", value:"2021-A-0057");

  script_name(english:"IBM MQ 7.5 / 8.0 / 9.0 < 9.0.0.11 LTS / 9.1 < 9.1.0.7 LTS / 9.2 < 9.2.0.1  LTS / 9.2 < 9.2.1 CD (6408626)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an unsafe deserialization vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM MQ Server running on the remote host is affected by a vulnerability. IBM MQ 7.5, 8.0, 9.0, 9.1, 9.2
LTS, and 9.2 CD could allow a remote attacker to execute arbitrary code on the system, caused by an unsafe
deserialization of trusted data. An attacker could exploit this vulnerability to execute arbitrary code on the system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6408626");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM MQ 9.0.0.11 LTS, 9.1.0.7 LTS, 9.2.0.1 LTS, 9.2.1 CD or later. Alternatively, install APAR IT33772 where appropriate.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4682");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

# Not checking for interim fix, so require paranoia for these versions only
if ((app_info['version'] =~ "^7.5" || app_info['version'] =~ "^8.0") && report_paranoia < 2)
  audit(AUDIT_PARANOID);

# check if CD - less than 4 version segments or non-0 3rd (M) segment
# https://www.ibm.com/support/pages/ibm-mq-faq-long-term-support-and-continuous-delivery-releases
# We see CD on lab host is detected as: 9.0.3.0
if (app_info['version'] =~ "^9\.([0-9]+\.?){0,2}$" || app_info['version'] =~ "^9\.[0-9]\.[1-9]")
{
  constraints = [
    { 'min_version' : '9.2', 'fixed_version' : '9.2.1'}
  ];
}
else
{
  constraints = [
    { 'min_version' : '7.5', 'fixed_version' : '7.6', 'fixed_display' : 'APAR IT33772'},
    { 'min_version' : '8.0', 'fixed_version' : '8.1', 'fixed_display' : 'APAR IT33772'},
    { 'min_version' : '9.0', 'fixed_version' : '9.0.0.11'},
    { 'min_version' : '9.1', 'fixed_version' : '9.1.0.7'},
    { 'min_version' : '9.2', 'fixed_version' : '9.2.0.1'}
  ];
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
