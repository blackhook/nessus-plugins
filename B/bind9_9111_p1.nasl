#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100996);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-3140", "CVE-2017-3141");
  script_bugtraq_id(99088, 99089);
  script_xref(name:"EDB-ID", value:"42121");

  script_name(english:"ISC BIND 9.x.x < 9.9.10-P1 / 9.10.x < 9.10.5-P1 / 9.11.x < 9.11.1-P1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of BIND.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of ISC
BIND running on the remote name server is 9.x.x prior to 9.9.10-P1,
9.10.x prior to 9.10.5-P1, or 9.11.x prior to 9.11.1-P1. It is,
therefore, affected by multiple vulnerabilities :

  - A denial of service vulnerability exists when processing
    Response Policy Zone (RPZ) rule types. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted query, to cause an infinite loop
    condition that degrades the server's functionality.
    (CVE-2017-3140)

  - A privilege escalation vulnerability exists in the BIND
    installer for Windows due to using an unquoted service
    path. A local attacker can exploit this to gain elevated
    privileges provided that the host file system
    permissions allow this. Note that non-Windows builds and
    installations are not affected. (CVE-2017-3141)");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/docs/aa-01495");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/docs/aa-01496");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ISC BIND version 9.9.10-P1 / 9.9.10-S2 / 9.10.5-P1 /
9.10.5-S2 / 9.11.1-P1 or later. Note that BIND 9 versions 9.9.10-S2
and 9.10.5-S2 are available exclusively for eligible ISC Support
customers.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3141");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

vcf::bind::initialize();

app_info = vcf::get_app_info(app:"BIND", port:53, kb_ver:"bind/version", service:TRUE, proto:"UDP");

if (report_paranoia < 2) audit(AUDIT_PARANOID); # patch can be applied

constraints = [
  { "min_version" : "9.2.6-P2", "max_version" : "9.2.9", "fixed_version" : "9.9.10-P1" },
  { "min_version" : "9.3.2-P1", "max_version" : "9.3.6", "fixed_version" : "9.9.10-P1" },
  { "min_version" : "9.4.0", "max_version" : "9.8.8", "fixed_version" : "9.9.10-P1" },
  { "min_version" : "9.9.3-S1", "fixed_version" : "9.9.10-S2" },
  { "min_version" : "9.9.0", "max_version" : "9.9.10", "fixed_version" : "9.9.10-P1" },
  { "min_version" : "9.9.10-S1", "fixed_version" : "9.9.10-S2" },
  { "min_version" : "9.10.5-S1", "fixed_version" : "9.10.5-S2" },
  { "min_version" : "9.10.0", "fixed_version" : "9.10.5-P1" },
  { "min_version" : "9.11.0", "max_version" : "9.11.1", "fixed_version" : "9.11.1-P1" }
];
constraints = vcf::bind::filter_constraints(constraints:constraints, version:app_info.version);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
