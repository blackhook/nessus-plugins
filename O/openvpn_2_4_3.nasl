#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(125262);
  script_version("1.4");
  script_cvs_date("Date: 2019/10/30 13:24:47");

  script_cve_id(
    "CVE-2017-7508",
    "CVE-2017-7520",
    "CVE-2017-7521",
    "CVE-2017-7522"
  );
  script_bugtraq_id(99230);

  script_name(english:"OpenVPN 2.3.x < 2.3.17 & 2.4.x < 2.4.3 Multiple Denial of Service Vulnerabilites (Windows)");
  script_summary(english:"Checks the version of OpenVPN.");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of OpenVPN installed on the remote Windows host is 2.3.x 
prior to 2.3.17 or 2.4.x prior to 2.4.3. It is, therefore, affected by multiple denial of service (DoS) vulnerabilities 
due to invalid input validation. An unauthenticated, remote attacker can exploit this issue, by sending malformed input,
to cause the application to stop responding.");
  # https://community.openvpn.net/openvpn/wiki/VulnerabilitiesFixedInOpenVPN243
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af9c7e6f");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenVPN 2.3.17 / 2.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7520");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/22");
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
  {'min_version': '2.3.0', 'fixed_version': '2.3.17'},
  {'min_version': '2.4.0', 'fixed_version': '2.4.3'}
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
