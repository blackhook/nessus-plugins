##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161326);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/27");

  script_cve_id("CVE-2022-1183");
  script_xref(name:"IAVA", value:"2022-A-0216-S");

  script_name(english:"ISC BIND 9.18.0 < 9.18.3 Assertion Failure (cve-2022-1183)");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by an assertion failure vulnerability vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ISC BIND installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the cve-2022-1183 advisory.

  - An assertion failure can be triggered if a TLS connection to a configured http TLS listener with a defined
    endpoint is destroyed too early.On vulnerable configurations, the named daemon may, in some circumstances,
    terminate with an assertion failure.  Vulnerable configurations are those that include a reference to
    http  within the  listen-on  statements in their  named.conf .  TLS is used by both DNS over TLS (DoT) and
    DNS over HTTPS (DoH), but configurations using DoT alone are unaffected. (CVE-2022-1183)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/v1/docs/cve-2022-1183");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ISC BIND version 9.18.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1183");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '9.18.0', 'max_version' : '9.18.2', 'fixed_version' : '9.18.3' }
];
constraints = vcf::bind::filter_constraints(constraints:constraints, version:app_info.version);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
