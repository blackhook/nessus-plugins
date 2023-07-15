#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105297);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2017-15942");
  script_bugtraq_id(102075);

  script_name(english:"Palo Alto Networks PAN-OS 7.1.x < 7.1.13 Management Interface Unspecified Remote DoS");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote PAN-OS host is affected by a Management Interface remote
DoS vulnerability.");
  script_set_attribute(attribute:"description",value:
"The version of Palo Alto Networks PAN-OS running on the remote host is
7.1.x prior to 7.1.13. It is, therefore, affected by a vulnerability
that allow a non-authenticated third party to mount a Denial of
Service attack against the management interface. Successful
exploitation of this issue allows an attacker to render the PAN-OS
management interface unavailable.");
  # https://securityadvisories.paloaltonetworks.com/Home/Detail/96
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?06c321db");
  # https://www.paloaltonetworks.com/documentation/71/pan-os/pan-os-release-notes/pan-os-7-1-13-addressed-issues
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd1a1ef2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 7.1.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15942");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/15");

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
  { 'min_version' : '7.1', 'fixed_version' : '7.1.13' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
