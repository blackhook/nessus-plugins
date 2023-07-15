#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(125261);
  script_version("1.6");
  script_cvs_date("Date: 2019/10/31 15:18:52");

  script_cve_id(
    "CVE-2005-2531",
    "CVE-2005-2532",
    "CVE-2005-2533",
    "CVE-2005-2534"
  );
  script_bugtraq_id(14605, 14607, 14610);

  script_name(english:"OpenVPN < 2.0.1 Multiple Vulnerabilities (Windows)");
  script_summary(english:"Checks the version of OpenVPN.");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of OpenVPN installed on the remote Windows host is prior to 
2.0.1. It is, therefore, affected by multiple vulnerabilities:
  
  - A denial of service (DoS) vulnerability exists in OpenVPN due to its OpenSSL error queue not being flushed properly.
    An unauthenticated, remote attacker can exploit this issue, by sending a large number of incorrect connection 
    requests, to cause the application to stop responding (CVE-2005-2531) & (CVE-2005-2532).

  - OpenVPN is affected by a denial of service (DoS) vulnerability. An authenticated, remote attacker can exploit this 
    issue, by sending a large of number of packets with spoofed MAC addresses, to cause the application to stop
    responding (CVE-2005-2533).

  - A denial of service (DoS) vulnerability exists in OpenVPN when --duplicate-cn is not enabled. An unauthenticated, 
    remote attacker can exploit this issue, by issuing simultaneous tcp connections from multiple clients that use the
    same certificate, to cause the application to stop responding (CVE-2005-2534).");
  # https://openvpn.net/community-resources/changelog-for-openvpn-2-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7dbca24");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenVPN 2.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-2532");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/16");
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

constraints = [{'fixed_version': '2.0.1'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
