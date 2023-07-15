#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(128773);
  script_version("1.4");
  script_cvs_date("Date: 2019/10/31 15:18:52");

  script_cve_id("CVE-2005-3409");
  script_bugtraq_id(15270);

  script_name(english:"OpenVPN Server 2.0.x < 2.0.4 Denial of Service Vulnerability");
  script_summary(english:"Checks the version of OpenVPN Server.");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote Windows host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of OpenVPN server installed on the remote Windows host is 
version 2.0.x prior to 2.0.4. It is, therefore, affected by a denial of service (DoS) vulnerability in its TCP/IP 
accept function component. An unauthenticated, remote attacker can exploit this issue, by forcing the accept function 
to return an error status which leads to a null dereference in an exception handler, to cause the application to stop 
responding.");
  script_set_attribute(attribute:"see_also", value:"http://openvpn.net/changelog.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenVPN 2.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-3409");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/16");

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

constraints = [{'min_version': '2.0.0', 'fixed_version': '2.0.4'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
