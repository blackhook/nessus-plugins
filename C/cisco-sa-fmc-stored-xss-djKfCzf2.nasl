#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149845);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2021-1238", "CVE-2021-1239");
  script_xref(name:"IAVA", value:"2021-A-0033-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt48601");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt99020");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fmc-stored-xss-djKfCzf2");

  script_name(english:"Cisco Firepower Management Center Multiple Stored XSS (cisco-sa-fmc-stored-xss-djKfCzf2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Firepower Management Center installed on the remote host is prior to 6.7.0. It is, therefore,
affected by multiple vulnerabilities as referenced in the cisco-sa-fmc-stored-xss-djKfCzf2 advisory. Specifically,
multiple vulnerabilities in the web-based management interface of Cisco Firepower Management Center (FMC) allow an
authenticated, remote attacker to conduct a stored cross-site scripting (XSS) attack against a user of the interface of
an affected system. The vulnerabilities exist because the web-based management interface does not properly validate
user-supplied input. An attacker could exploit these vulnerabilities by persuading a user of the interface to click a
crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the
affected interface or access sensitive, browser-based information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-stored-xss-djKfCzf2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?603e151b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt48601");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt99020");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvt48601, CSCvt99020");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1238");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_management_center");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Cisco Firepower Management Center', kb_ver:'Host/Cisco/firepower_mc/version');
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '6.7.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE, flags:{'xss':TRUE});

