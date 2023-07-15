#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106143);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2017-15941", "CVE-2017-16878", "CVE-2017-17841");
  script_bugtraq_id(102446);

  script_name(english:"Palo Alto Networks PAN-OS 7.1.x < 7.1.15 /  8.0.x < 8.0.7 Multiple Vulnerabilities (ROBOT)");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote PAN-OS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Palo Alto Networks PAN-OS running on the remote host is
7.1.x prior to 7.1.15 or 8.0.x prior to 8.0.7. It is, therefore, 
affected by multiple vulnerabilities.");
  # https://securityadvisories.paloaltonetworks.com/Home/Detail/111
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55515506");
  # https://securityadvisories.paloaltonetworks.com/Home/Detail/114
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d694cf06");
  # https://securityadvisories.paloaltonetworks.com/Home/Detail/117
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ae44cf2");
  # https://www.paloaltonetworks.com/documentation/71/pan-os/pan-os-release-notes/pan-os-7-1-15-addressed-issues
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee509a71");
  # https://www.paloaltonetworks.com/documentation/80/pan-os/pan-os-release-notes/pan-os-8-0-7-addressed-issues
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6a0ebb6");
  script_set_attribute(attribute:"see_also", value:"https://robotattack.org/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 7.1.15 / 8.0.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15941");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
  { 'min_version' : '7.1', 'fixed_version' : '7.1.15' },
  { 'min_version' : '8.0', 'fixed_version' : '8.0.7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
