#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(125260);
  script_version("1.6");
  script_cvs_date("Date: 2019/10/31 15:18:52");

  script_cve_id("CVE-2013-2061");

  script_name(english:"OpenVPN < 2.3.1 Information Disclosure Vulnerability (Windows)");
  script_summary(english:"Checks the version of OpenVPN.");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote Windows host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of OpenVPN installed on the remote Windows host is prior to 
2.3.1. It is, therefore, affected by an information disclosure vulnerability in the crypto.c component due to its HMAC 
comparison function not running in constant time. An unauthenticated, remote attacker can exploit this, via a timing 
attack, to disclose potentially sensitive information.");
  # https://community.openvpn.net/openvpn/wiki/SecurityAnnouncement-f375aa67cc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56e4cef7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenVPN 2.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2061");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openvpn:openvpn");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openvpn_server_installed.nbin");
  script_require_keys("installed_sw/OpenVPN Server");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'OpenVPN Server');

constraints = [{'fixed_version': '2.3.1'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
