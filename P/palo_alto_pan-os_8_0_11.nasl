#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111065);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id(
    "CVE-2018-7636", 
    "CVE-2018-9242", 
    "CVE-2018-9334", 
    "CVE-2018-9335"
);

  script_name(english:"Palo Alto Networks PAN-OS 6.x.x < 6.1.21 /  7.1.x < 7.1.18 /  8.0.x < 8.0.11-h1 Multiple Vulnerabilities");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote PAN-OS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Palo Alto Networks PAN-OS running on the remote host
is 6.x.x prior to 6.1.21 or 7.1.x prior to 7.1.15 or 8.0.x prior to
8.0.11-h3 It is, therefore, affected by multiple vulnerabilities.");
  # https://securityadvisories.paloaltonetworks.com/Home/Detail/122
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8af038a9");
  # https://securityadvisories.paloaltonetworks.com/Home/Detail/123
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67e06e9b");
  # https://securityadvisories.paloaltonetworks.com/Home/Detail/124
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc5becfb");
  # https://securityadvisories.paloaltonetworks.com/Home/Detail/126
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4c630d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 6.1.21 / 7.1.18 / 8.0.11-h1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-9242");
  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/13");

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
  { "min_version" : "6.0", "fixed_version" : "6.1.21" },
  { 'min_version' : '7.0', 'fixed_version' : '7.1.18' },
  { 'min_version' : '8.0', 'fixed_version' : '8.0.11-h1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
