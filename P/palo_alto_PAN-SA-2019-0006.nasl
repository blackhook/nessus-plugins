#
# (C) Tenable Network Security, Inc.
#
# @NOAGENT@

include("compat.inc");

if (description)
{
  script_id(123079);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2018-14634");
  script_bugtraq_id(105407);

  script_name(english:"Palo Alto Networks < 7.1.23 / 8.0.x < 8.0.16 / 8.1.x < 8.1.7 Integer Overflow Vulnerability (PAN-SA-2019-0006)");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by integer overflow vulnerability in the Linux Kernel that exists in the PAN-OS");
  script_set_attribute(attribute:"description",value:
"The version of Palo Alto Networks PAN-OS running on the remote host
is prior to 7.1.23 or 8.0.x prior to 8.0.16 or 8.1.x prior to 8.1.7.
It is, therefore, affected by an integer overflow vulnerability exists
in the Linux Kernel of PAN-OS. An authenticated, local attacker can
exploit this, via execution of arbitrary code in chained attack.
(CVE-2018-14634)");
  #https://securityadvisories.paloaltonetworks.com/Home/Detail/143
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2afacfa4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 7.1.23 / 8.0.16 / 8.1.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14634");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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

model = get_kb_item_or_exit('Host/Palo_Alto/Firewall/Model');

constraints = [];

# M-500 and WF-500
if (
  model =~ 'M-500' ||
  model =~ 'WF-500'
  )
{
  constraints = [
    { 'fixed_version' : '7.1.23' },
    { 'min_version' : '8.0', 'fixed_version' : '8.0.16' },
    { 'min_version' : '8.1', 'fixed_version' : '8.1.7' }
  ];
}
# M-600
else if (model =~ 'M-600')
{
  constraints = [
    { 'min_version' : '8.1', 'fixed_version' : '8.1.7' }
  ];
}
# PA-5220, PA-5250, PA-5260
else if (
  model =~ 'PA-5220' ||
  model =~ 'PA-5250' ||
  model =~ 'PA-5260' ||
  model =~ 'PA-5280'
  )
{
  constraints = [
    { 'min_version' : '8.0', 'fixed_version' : '8.0.16' },
    { 'min_version' : '8.1', 'fixed_version' : '8.1.7' }
  ];
}
else
  audit(AUDIT_HOST_NOT, 'an affected model');

# We cannot test for the full vulnerable condition
# 64bit systems with more than 32 GB
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
