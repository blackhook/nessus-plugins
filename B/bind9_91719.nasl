#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154662);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/27");

  script_cve_id("CVE-2021-25219");
  script_xref(name:"IAVA", value:"2021-A-0525-S");

  script_name(english:"ISC BIND 9.3.0 < 9.11.36 / 9.9.3-S1 < 9.11.36-S1 / 9.12.0 < 9.16.22 / 9.16.8-S1 < 9.16.22-S1 / 9.17.0 < 9.17.19 Vulnerability (CVE-2021-25219)");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a vulnerability vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ISC BIND installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the CVE-2021-25219 advisory.

  - In BIND 9.3.0 -> 9.11.35, 9.12.0 -> 9.16.21, and versions 9.9.3-S1 -> 9.11.35-S1 and 9.16.8-S1 ->
    9.16.21-S1 of BIND Supported Preview Edition, as well as release versions 9.17.0 -> 9.17.18 of the BIND
    9.17 development branch, exploitation of broken authoritative servers using a flaw in response processing
    can cause degradation in BIND resolver performance. The way the lame cache is currently designed makes it
    possible for its internal data structures to grow almost infinitely, which may cause significant delays in
    client query processing. (CVE-2021-25219)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/v1/docs/CVE-2021-25219");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ISC BIND version 9.11.36 / 9.11.36-S1 / 9.16.22 / 9.16.22-S1 / 9.17.19 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25219");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::bind::initialize();

var app_info = vcf::get_app_info(app:'BIND', port:53, kb_ver:'bind/version', service:TRUE, proto:'UDP');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var constraints = [
  { 'min_version' : '9.3.0', 'max_version' : '9.11.35', 'fixed_version' : '9.11.36' },
  { 'min_version' : '9.9.3-S1', 'max_version' : '9.11.35-S1', 'fixed_version' : '9.11.36-S1' },
  { 'min_version' : '9.12.0', 'max_version' : '9.16.21', 'fixed_version' : '9.16.22' },
  { 'min_version' : '9.16.8-S1', 'max_version' : '9.16.21-S1', 'fixed_version' : '9.16.22-S1' },
  { 'min_version' : '9.17.0', 'max_version' : '9.17.18', 'fixed_version' : '9.17.19' }
];
constraints = vcf::bind::filter_constraints(constraints:constraints, version:app_info.version);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
