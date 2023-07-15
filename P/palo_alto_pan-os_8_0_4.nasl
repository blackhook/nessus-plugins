#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103222);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2017-6460");
  script_bugtraq_id(97052);

  script_name(english:"Palo Alto Networks PAN-OS 6.1.x / 7.0.x < 7.0.18 / 7.1.x < 7.1.12 / 8.0.x < 8.0.4 Network Time Protocol Vulnerability");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote PAN-OS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Palo Alto Networks PAN-OS running on the remote host is
6.1.x, 7.0.x prior to 7.0.18, 7.1.x prior to 7.1.12, or 8.0.x prior to
8.0.4. It is, therefore, affected by a vulnerability in the reslist()
function in ntpq/ntpq-subs.c. An attacker can cause a stack-based
buffer overflow to cause a denial of service or potentially execute
arbitrary code. Note the attacker must be on the management interface
to exploit this vulnerability.");
  # https://www.paloaltonetworks.com/documentation/80/pan-os/pan-os-release-notes/pan-os-8-0-4-addressed-issues
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?639c2b91");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/92");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 7.0.18 / 7.1.12
/ 8.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6460");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '6.1', 'max_version' : '6.2', 'fixed_version' : '7.0.18' },
  { 'min_version' : '7.0', 'max_version' : '7.0.17', 'fixed_version' : '7.0.18' },
  { 'min_version' : '7.1', 'max_version' : '7.1.11', 'fixed_version' : '7.1.12' },
  { 'min_version' : '8.0', 'max_version' : '8.0.3', 'fixed_version' : '8.0.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
