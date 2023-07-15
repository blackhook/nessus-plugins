#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137837);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/28");

  script_cve_id("CVE-2020-8619");
  script_xref(name:"IAVA", value:"2020-A-0276-S");

  script_name(english:"ISC BIND 9.11.x < 9.11.20 / 9.11.14-S1 < 9.11.19-S9 / 9.14.x < 9.14.13 / 9.16.x < 9.16.4 DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ISC BIND installed on the remote host is affected by a denial of service (DoS) vulnerability in 
  rbtdb.c due to an assertion failure. An authenticated, remote attacker can exploit this issue, to cause a DoS 
  condition. 

  Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
  version");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/docs/cve-2020-8619");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ISC BIND version 9.11.19-S9 / 9.11.20 / 9.14.13 / 9.16.4 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8619");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::bind::initialize();
app_info = vcf::get_app_info(
  app:'BIND',
  port:53,
  kb_ver:'bind/version',
  service:TRUE,
  proto:'UDP'
);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

constraints = [
  { 'min_version' : '9.11.0', 'fixed_version' : '9.11.20' },
  { 'min_version' : '9.11.14-S1', 'fixed_version' : '9.11.19-S9' },
  { 'min_version' : '9.14.0', 'fixed_version' : '9.14.13' },
  { 'min_version' : '9.16.0', 'fixed_version' : '9.16.4' },
];

constraints = vcf::bind::filter_constraints(
  constraints:constraints,
  version:app_info.version
);

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
