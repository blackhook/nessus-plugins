#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125404);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/28 10:52:49");

  script_name(english:"Fortinet FortiClient 6.2.x < 6.2.1 Missing Encryption Of Sensitive Data Vulnerability (macOS)");
  script_summary(english:"Checks the version of FortiClient.");

  script_set_attribute(attribute:"synopsis", value:
"The remote MacOS is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Fortinet FortiClient Mac running on the remote host is
prior to 6.2.1. It is, therefore, affected by a missing encryption of 
sensitive data vulnerability. An attacker can access VPN session cookie
from an endpoint device running FortiClient. The attacker can steal the
cookies only if endpoint device has been compromised in such a way that
the attacker has access to FortiClient's debug logs or memory space. 
Furthermore, practical use of the stolen cookie requires the attacker
to spoof the endpoint's IP address.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-19-110");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiClient 6.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on analysis of vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macos_forticlient_detect.nbin");
  script_require_keys("installed_sw/FortiClient (macOS)");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit('installed_sw/FortiClient (macOS)');
app_info = vcf::get_app_info(app:'FortiClient (macOS)');

constraints = [
  {'min_version' : '6.2.0', 'fixed_version' : '6.2.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
