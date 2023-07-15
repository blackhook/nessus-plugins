#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(105298);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/19");

  script_cve_id("CVE-2017-15940", "CVE-2017-15943", "CVE-2017-15944");
  script_bugtraq_id(102074, 102076, 102079);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/08");

  script_name(english:"Palo Alto Networks PAN-OS 7.1.x < 7.1.14 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote PAN-OS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Palo Alto Networks PAN-OS running on the remote host is
7.1.x prior to 7.1.14. It is, therefore, affected by multiple
vulnerabilities.");
  # https://securityadvisories.paloaltonetworks.com/Home/Detail/96
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?06c321db");
  # https://securityadvisories.paloaltonetworks.com/Home/Detail/102
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9a7eb24");
  # https://www.paloaltonetworks.com/documentation/71/pan-os/pan-os-release-notes/pan-os-7-1-14-addressed-issues
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?510a76d9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 7.1.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15940");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-15944");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Palo Alto Networks readSessionVarsFromFile() Session Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version", "Host/Palo_Alto/Firewall/Source");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::palo_alto::initialize();

app_name = 'Palo Alto Networks PAN-OS';

app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Palo_Alto/Firewall/Full_Version', kb_source:'Host/Palo_Alto/Firewall/Source');

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '7.1', 'fixed_version' : '7.1.14' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
