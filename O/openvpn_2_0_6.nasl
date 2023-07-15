#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(125643);
  script_version("1.4");
  script_cvs_date("Date: 2019/10/31 15:18:52");

  script_cve_id("CVE-2006-1629");
  script_bugtraq_id(17392);

  script_name(english:"OpenVPN Client 2.0.x < 2.0.6 Remote Code Execution Vulnerability");
  script_summary(english:"Checks the version of OpenVPN.");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote Windows host is affected by a remote 
  code execution vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of OpenVPN client installed on the remote Windows host is 2.0.x 
prior to 2.0.6. It is, therefore, affected by a remote command execution vulnerability. An unauthenticated remote 
attacker can exploit this by deploying a malicious OpenVPN server and executing code on clients' systems by using 
setenv with the LD_PRELOAD environment variable.");
  # https://openvpn.net/community-resources/changelog-for-openvpn-2-0/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6534e9a2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenVPN 2.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-1629");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openvpn:openvpn");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openvpn_installed.nbin");
  script_require_keys("installed_sw/OpenVPN");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'OpenVPN');

constraints = [
  {'min_version': '2.0.0', 'fixed_version': '2.0.6'}
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
