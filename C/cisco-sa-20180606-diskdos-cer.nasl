#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130068);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/30 13:24:46");

  script_cve_id("CVE-2017-6779");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf64322");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180606-diskdos");

  script_name(english:"Cisco Emergency Responder Denial of Service (cisco-sa-20180606-diskdos)");
  script_summary(english:"Checks the Cisco Emergency Responder (CER) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Emergency Responder (CER) is affected by a denial of service 
vulnerability. The vulnerability occurs because a certain system log file does not have a maximum size restriction. This
could allow an unauthenticated, remote attacker to cause high disk utilization, resulting in a denial of service (DoS)
condition.");
# https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180606-diskdos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6ab2b07");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf64322");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to the version recommended in Cisco bug ID CSCvf64322");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6779");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:emergency_responder");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("cisco_voss_emergency_responder_installed.nbin");
  script_require_keys("installed_sw/Cisco Emergency Responder (CER)");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
include('audit.inc');

app_info = vcf::get_app_info(app:'Cisco Emergency Responder (CER)');

constraints = [
  { 'min_version':'0.0.0', 'max_version':'10.5.1.20000.3', 'required_cop':"CSCvf64322.cop", 'fixed_display':'10.5(1a) & ciscocm.cer_CSCvf64322.cop, Bug ID: CSCvf64322' },
  { 'min_version':'11.0.0', 'fixed_version':'11.5.4.20000.3', 'fixed_display':'11.5(4), Bug ID: CSCvf64322' },
  { 'min_version':'12.0.0', 'fixed_version':'12.0.1.20000.4', 'fixed_display':'12.0(1)SU1, Bug ID: CSCvf64322' }
];

vcf::cisco_cer::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
