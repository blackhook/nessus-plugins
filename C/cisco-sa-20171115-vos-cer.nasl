#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130067);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/30 13:24:46");

  script_cve_id("CVE-2017-12337");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg55112");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171115-vos");

  script_name(english:"Cisco Emergency Responder Denial of Service (cisco-sa-20171115-vos)");
  script_summary(english:"Checks the Cisco Emergency Responder (CER) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Emergency Responder (CER) is affected by an unauthorized access
vulnerability. The vulnerability in the upgrade mechanism of Cisco collaboration products based on the Cisco Voice 
Operating System software platform could allow an unauthenticated, remote attacker to gain unauthorized, elevated access
to an affected device. The vulnerability occurs when a refresh upgrade (RU) or Prime Collaboration Deployment (PCD) 
migration is performed on an affected device. When a refresh upgrade or PCD migration is completed successfully, 
an engineering flag remains enabled and could allow root access to the device with a known password.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171115-vos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e2c1cc2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg55112");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to the version recommended in Cisco bug ID CSCvg55112");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12337");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/15");
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
  { 'min_version':'8.6.0', 'max_version':'9.1.99', 'required_cop':"CSCvg22923-v1\.2\.cop", 'fixed_display':'ciscocm.CSCvg22923-v1.2.cop, Bug ID: CSCvg55112' },
  { 'min_version':'10.0.0', 'fixed_version':'11.5.4.20000.2', 'required_cop':"CSCvg22923-v1\.2\.k3\.cop", 'fixed_display':'ciscocm.CSCvg22923-v1.2.k3.cop, Bug ID: CSCvg55112' },
  { 'min_version':'12.0.0', 'fixed_version':'12.0.1.11900.5', 'required_cop':"CSCvg22923-v1\.2\.k3\.cop", 'fixed_display':'ciscocm.CSCvg22923-v1.2.k3.cop, Bug ID: CSCvg55112' }
];

vcf::cisco_cer::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
