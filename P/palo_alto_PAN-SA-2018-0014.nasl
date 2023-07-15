#
# (C)  Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(122822);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2018-10141");
  script_bugtraq_id(106994);

  script_name(english:"Palo Alto Networks PAN-OS < 6.1 / 7.x < 7.1 / 8.1.x < 8.1.4 Cross-Site Scripting Vulnerability (PAN-SA-2018-0014)");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by cross-site scripting (XSS) vulnerability in PAN-OS GlobalProtect login page.");
  script_set_attribute(attribute:"description", value:
"The version of Palo Alto Networks PAN-OS running on the remote host
is prior to 6.1, 7.x prior to 7.1, 8.1.x prior to 8.1.4. It is,
therefore, affected by a cross-site scripting (XSS) vulnerability that
exists in PAN-OS GlobalProtect portal login page due to improper
validation of user-supplied input before returning it to users. An
unauthenticated, remote attacker can exploit this, by convincing a
user to click a specially crafted URL, to execute arbitrary script
code in a user's browser session. (CVE-2018-10141)");
  # https://securityadvisories.paloaltonetworks.com/Home/Detail/134
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8bd083ea");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS 6.1.x, 7.1.x, 8.0.x, 8.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10141");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/14");

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
  { 'fixed_version' : '6.1' },
  { 'min_version' : '7.0', 'fixed_version' : '7.1' },
  { 'min_version' : '8.1', 'fixed_version' : '8.1.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
