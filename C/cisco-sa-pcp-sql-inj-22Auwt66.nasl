#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139665);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/03");

  script_cve_id("CVE-2020-3184");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs29296");
  script_xref(name:"CISCO-SA", value:"cisco-sa-pcp-sql-inj-22Auwt66");
  script_xref(name:"IAVA", value:"2020-A-0110-S");

  script_name(english:"Cisco Prime Collaboration Provisioning Software SQL Injection (cisco-sa-pcp-sql-inj-22Auwt66)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, a vulnerability in the web-based management interface of Cisco Prime
Collaboration Provisioning Software could allow an authenticated, remote attacker to conduct SQL injection attacks
on an affected system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-pcp-sql-inj-22Auwt66
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e29d138b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs29296");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs29296");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3184");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/18");

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

app = 'Prime Collaboration Provisioning';
app_info = vcf::get_app_info(app:app, kb_ver:'Host/Cisco/PrimeCollaborationProvisioning/version');

if (app_info['version'] == '12')
  audit(AUDIT_VER_NOT_GRANULAR, app, app_info['version']);

constraints = [
  { 'min_version' : '0.0', 'max_version' : '12.6.0.3039', 'fixed_display' : '12.6 SU2'}
]; 

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
