#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140631);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/18");

  script_cve_id("CVE-2020-3113");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs04009");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200219-dcnm-xss");

  script_name(english:"Cisco Data Center Network Manager Stored Cross-Site Scripting (cisco-sa-20200219-dcnm-xss)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Data Center Network Manager is prior to version 11.3(1) and is,
therefore, affected by a cross-site scripting vulnerability in the web-based management interface due to insufficient
validation of user-supplied input. An attacker could exploit this vulnerability by persuading a user of the interface
to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the context
of the interface or access sensitive, browser-based information. Please see the included Cisco BID and Cisco Security
Advisory for more information.");
  # http://tools.cisco.com/security/center/content/CiscoAppliedMitigationBulletin/cisco-amb-20060922-understanding-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1596bcb6");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200219-dcnm-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96f7dae4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs04009");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs04009");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3113");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:data_center_network_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_dcnm_installed_win.nasl", "cisco_prime_dcnm_installed_linux.nasl", "cisco_prime_dcnm_web_detect.nasl");
  script_require_keys("installed_sw/Cisco Prime DCNM", "installed_sw/cisco_dcnm_web");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::cisco_dcnm_web::get_app_info();
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'fixed_version' : '11.3.1.0', 'fixed_display' : '11.3(1)' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE,
  flags:{xss:TRUE}
);

