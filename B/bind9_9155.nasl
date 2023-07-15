#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130212);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2019-6475", "CVE-2019-6476");
  script_xref(name:"IAVA", value:"2019-A-0397-S");

  script_name(english:"ISC BIND 9.14.x < 9.14.7 / 9.15.x < 9.15.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of ISC BIND.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"ISC BIND versions 9.14.6 / 9.15.4 and earlier are affected by multiple vulnerabilities.
  - A flaw in mirror zone validity checking. It can allow zone data to be spoofed.
    (CVE-2019-6475)

  - A defect in code added to support QNAME minimization can cause named to exit with an
    assertion failure if a forwarder returns a referral rather than resolving the query.
    (CVE-2019-6476)");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/docs/cve-2019-6475");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/docs/cve-2019-6476");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/docs/aa-00913");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/docs/aa-00861");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ISC BIND version 9.14.7 / 9.15.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6475");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::bind::initialize();

app_info = vcf::get_app_info(app:'BIND', port:53, kb_ver:'bind/version', service:TRUE, proto:'UDP');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

constraints = [
  { 'min_version' : '9.14.0', 'max_version' : '9.14.6' },
  { 'min_version' : '9.15.0', 'max_version' : '9.15.4' }
];
constraints = vcf::bind::filter_constraints(constraints:constraints, version:app_info.version);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
