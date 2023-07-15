#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125226);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2016-6329");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"OpenVPN < 2.3.15 Weak Cryptographic Cipher Vulnerability (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote Windows host is affected by a weak cryptographic cipher vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of OpenVPN installed on the remote Windows host is prior to 
2.3.15. It is, therefore, affected by a weak cryptographic cipher vulnerability. OpenVPN's default cipher, BF-CBC, is 
vulnerable to plaintext recovery when enough cipher text has been observed. An unauthenticated, remote attacker can 
exploit this issue, to decrypt data being sent to OpenVPN.");
  # https://community.openvpn.net/openvpn/wiki/SWEET32
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a339f210");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenVPN 2.3.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6329");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openvpn:openvpn");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openvpn_server_installed.nbin");
  script_require_keys("installed_sw/OpenVPN Server");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'OpenVPN Server');

constraints = [{'fixed_version': '2.3.15'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
