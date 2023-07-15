#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112161);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2018-10139", "CVE-2018-10140");
  script_bugtraq_id(105107, 105111);

  script_name(english:"Palo Alto Networks PAN-OS 6.1.21 and earlier /  7.1.x < 7.1.19 /  8.0.x < 8.0.12 /  8.1.x < 8.1.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote PAN-OS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Palo Alto Networks PAN-OS running on the remote host
is 6.x.x or 7.1.x prior to 7.1.19 or 8.0.x prior to 8.0.12 or 8.1.x 
prior to 8.1.3. It is, therefore, affected by multiple 
vulnerabilities.");
  # https://securityadvisories.paloaltonetworks.com/Home/Detail/128
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f828553");
  # https://securityadvisories.paloaltonetworks.com/Home/Detail/129
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e379ee3f");
  script_set_attribute(attribute:"see_also", value:"http://www.paloaltonetworks.com/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PAN-OS 7.1.19 / 8.0.12 / 8.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10139");
  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '6.0', 'max_version' : '6.1.21', 'fixed_version' : 'Check Palo Alto Networks website for solutions.' },
  { 'min_version' : '7.0', 'fixed_version' : '7.1.19' },
  { 'min_version' : '8.0', 'fixed_version' : '8.0.12' },
  { 'min_version' : '8.1', 'fixed_version' : '8.1.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
