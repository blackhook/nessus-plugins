#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(125259);
  script_version("1.4");
  script_cvs_date("Date: 2019/05/27  8:35:26");

  script_cve_id("CVE-2017-7478");
  script_bugtraq_id(98444);

  script_name(english:"OpenVPN 2.3.12 < 2.3.15 / 2.4.x < 2.4.2 Denial of Service Vulnerability (Windows)");
  script_summary(english:"Checks the version of OpenVPN.");

  script_set_attribute(attribute:"synopsis", value:"An application on the remote Windows host is affected by a denial 
  of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of OpenVPN installed on the remote Windows host is 2.3.12
prior to 2.3.15 or 2.4.x prior to 2.4.2. It is, therefore, affected by a denial of service (DoS) vulnerability due to 
invalid packet processing logic. An unauthenticated, remote attacker can exploit this issue, by sending a large control 
packet, to cause the application to stop responding.");
  # https://community.openvpn.net/openvpn/wiki/QuarkslabAndCryptographyEngineerAudits
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c722f7c");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenVPN 2.3.15 / 2.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7478");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/11");
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

constraints = [
  {'min_version': '2.3.12', 'fixed_version': '2.3.15'},
  {'min_version': '2.4.0', 'fixed_version': '2.4.2'}
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
