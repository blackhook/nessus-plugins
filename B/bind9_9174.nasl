#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139911);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-8624");
  script_xref(name:"IAVA", value:"2020-A-0385-S");

  script_name(english:"ISC BIND Zone Update Vulnerability (cve-2020-8624)");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"ISC BIND versions 9.9.12 to 9.9.13, 9.10.7 to 9.10.8, 9.11.3 to 9.11.21, 9.12.1 to 9.16.5, 9.17.0 to 9.17.3 as well as
9.9.12-S1 to 9.9.13-S1, 9.11.3-S1 to 9.11.21-S1 of the BIND 9 Supported Preview Edition are affected by a vulnerability.
An authenticated, remote attacker who has been granted privileges to change a specific subset of the zone's content can
exploit this to update other contents of the zone. This is because 'update-policy' rules of the type 'subdomain' were
inadvertently treated as if they were of type 'zonesub'. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/docs/cve-2020-8624");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ISC BIND whichever of the following versions is most closely related to your current version of BIND:
9.11.22, 9.16.6, 9.17.4, or 9.11.22-S1 for BIND Supported Preview Edition");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8624");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::bind::initialize();

app_info = vcf::get_app_info(app:'BIND', port:53, kb_ver:'bind/version', service:TRUE, proto:'UDP');

constraints = [
  { 'min_version' : '9.9.12', 'max_version' : '9.9.13', 'fixed_display':'9.11.22'},
  { 'min_version' : '9.10.7', 'max_version' : '9.10.8', 'fixed_display':'9.11.22'},
  { 'min_version' : '9.11.3', 'max_version' : '9.11.21', 'fixed_display':'9.11.22'},
  { 'min_version' : '9.12.1', 'max_version' : '9.16.5', 'fixed_display':'9.16.6'},
  { 'min_version' : '9.17.0', 'max_version' : '9.17.3', 'fixed_display':'9.17.4'},
  { 'min_version' : '9.9.12-S1', 'max_version' : '9.9.13-S1', 'fixed_display':'9.11.22-S1'},
  { 'min_version' : '9.11.3-S1', 'max_version' : '9.11.21-S1', 'fixed_display':'9.11.22-S1'}
];
constraints = vcf::bind::filter_constraints(constraints:constraints, version:app_info.version);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

