#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134711);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/03");

  script_cve_id("CVE-2020-3192");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs29654");
  script_xref(name:"CISCO-SA", value:"cisco-sa-prime-collab-xss-RjRCe9n7");
  script_xref(name:"IAVA", value:"2020-A-0110-S");

  script_name(english:"Cisco Prime Collaboration Provisioning Cross-Site Scripting Vulnerability (cisco-sa-prime-collab-xss-RjRCe9n7)");

  script_set_attribute(attribute:"synopsis", value:
"The remote network management server is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Prime Collaboration Provisioning is affected by a cross-site scripting
vulnerability in the web-based management interface due to insufficient validation of user-supplied input. An 
unauthenticated, remote attacker could exploit this by persuading a user of the interface to click a on a specially
crafted link, allowing the attacker to execute arbitrary script code in the context of the interface, or disclose
sensitive information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-prime-collab-xss-RjRCe9n7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cdc4c037");
  # https://tools.cisco.com/security/center/content/CiscoAppliedMitigationBulletin/cisco-amb-20060922-understanding-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4162caf8");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs29654
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7bcaa50");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs29654");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3192");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_collaboration_provisioning");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_collaboration_provisioning_detect.nbin");
  script_require_keys("Host/Cisco/PrimeCollaborationProvisioning/version");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/local_checks_enabled');
app = 'Prime Collaboration Provisioning';
app_info = vcf::get_app_info(app:app, kb_ver:'Host/Cisco/PrimeCollaborationProvisioning/version');

constraints = [
  { 'min_version' : '1.0', 'max_version' : '12.6.0.2742', 'fixed_display':'Refer to Cisco Bug ID: CSCvs29654' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
