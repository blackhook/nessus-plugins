#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(144504);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/22");

  script_cve_id("CVE-2018-15389");
  script_bugtraq_id(105942);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd86564");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181003-cpcp-password");

  script_name(english:"Cisco Prime Collaboration Provisioning Intermittent Hard-Coded Password (cisco-sa-20181003-cpcp-password)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Cisco Prime Collaboration Provisioning server is prior to 
12.1. It is, therefore, affected by a vulnerability in the install function that could allow an unauthenticated, remote 
attacker to access the administrative web interface using a default hard-coded username and password that are used 
during install.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181003-cpcp-password
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56350323");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd86564");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvd86564");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15389");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(255);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_collaboration_provisioning");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_collaboration_provisioning_detect.nbin");
  script_require_keys("Host/Cisco/PrimeCollaborationProvisioning/version");

  exit(0);
}

include('vcf.inc');

app = 'Prime Collaboration Provisioning';
app_info = vcf::get_app_info(app:app, kb_ver:'Host/Cisco/PrimeCollaborationProvisioning/version');

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'fixed_version' : '12.1' }
]; 

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
