#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172427);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/28");

  script_cve_id("CVE-2023-20069");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd61777");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cisco-pi-epnm-xss-mZShH2J");
  script_xref(name:"IAVA", value:"2023-A-0219");

  script_name(english:"Cisco Prime Infrastructure Stored XSS (cisco-sa-cisco-pi-epnm-xss-mZShH2J)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Prime Infrastructure installed on the remote host is prior to 3.10.3. It is, therefore,
affected by a cross-site scripting (XSS)vulnerability as referenced in the cisco-sa-cisco-pi-epnm-xss-mZShH2J advisory.
This vulnerability is due to insufficient validation of user-supplied input. An authenticated, remote attacker could
exploit this vulnerability by persuading a user of an affected interface to click a crafted link. A successful exploit
could allow the attacker to execute arbitrary script code in the context of the affected interface or access sensitive,
browser-based information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cisco-pi-epnm-xss-mZShH2J
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?344c5b5c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd61777");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwd61777");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20069");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_infrastructure");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_infrastructure_detect.nbin");
  script_require_keys("installed_sw/Prime Infrastructure");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Prime Infrastructure');

vcf::check_granularity(app_info:app_info, sig_segments:3);
var constraints = [
  {'fixed_version': '3.10.3'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{'xss':TRUE});
