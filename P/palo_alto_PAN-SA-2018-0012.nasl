#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(122259);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2018-5391");
  script_bugtraq_id(105108);

  script_name(english:"Palo Alto Networks PAN-OS 6.1.x < 6.1.22 / 7.1.x < 7.1.20 / 8.0.x < 8.0.13 / 8.1.x < 8.1.5 Multiple Vulnerabilities (PAN-SA-2018-0012)");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Palo Alto Networks PAN-OS running on the remote host is
6.0.x prior to 6.1.22 or 7.1.x prior to 7.1.22 or 8.0.x prior to 8.0.13 
or 8.1.x prior to 8.1.5. It is, therefore, affected by multiple 
vulnerabilities :

  - Management Plane of Palo Alto PAN-OS is affected by FragmentSmack
    vulnerability. A remote attacker could send specially crafted packets
    which can trigger CPU saturation (a denial of service on the system).
    (CVE-2018-5391)");
  # https://securityadvisories.paloaltonetworks.com/Home/Detail/131
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2dfafb7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 6.1.22 / 7.1.22 / 8.0.13 / 8.1.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5391");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '6.1', 'fixed_version' : '6.1.22' },
  { 'min_version' : '7.1', 'fixed_version' : '7.1.20' },
  { 'min_version' : '8.0', 'fixed_version' : '8.0.13' },
  { 'min_version' : '8.1', 'fixed_version' : '8.1.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
