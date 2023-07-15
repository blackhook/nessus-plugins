##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141500);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/20");

  script_cve_id("CVE-2019-16025");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr15545");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200108-er-xss");

  script_name(english:"Cisco Emergency Responder Open Redirect XSS (cisco-sa-20200108-er-xss)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Emergency Responder (CER) is affected by a cross-site scripting
vulnerability in the web-based management interface due to insufficient validation of user-supplied input. An
authenticated, remote attacker could exploit this by persuading a user of the interface to click a malicious link or
by intercepting a user request for the affected web interface and injecting malicious code into the request. A
successful exploit could allow the attacker to execute arbitrary script code in the context of the affected web
interface or allow the attacker to access sensitive browser-based information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200108-er-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3cf84716");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr15545");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr15545");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16025");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:emergency_responder");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_voss_emergency_responder_installed.nbin");
  script_require_keys("installed_sw/Cisco Emergency Responder (CER)");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Cisco Emergency Responder (CER)');

# Known Affected Releases:
# 12.5(1)SU1 = 12.51(19000.38)

# Known Fixed Releases:
# 12.5(1.21900.11)

constraints = [
  { 'max_version' : '12.5.1.19000.38', 'fixed_version' : '12.5.1.21900.11', 'fixed_display' : '12.5(1.21900.11)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE, flags: {'xss':TRUE});
