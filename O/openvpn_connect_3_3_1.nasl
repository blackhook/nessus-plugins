#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154347);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_cve_id("CVE-2021-3613");
  script_xref(name:"IAVA", value:"2021-A-0490");

  script_name(english:"OpenVPN Connect 3.2.0 < 3.3.1 Input Validation Vulnerability (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote Windows host is affected by an input validation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of OpenVPN Connect installed on the remote Windows host is 
affected by an input validation vulnerability. OpenVPN Connect 3.2.0 through 3.3.0 allows local users to load arbitrary 
dynamic loadable libraries via an OpenSSL configuration file if present, which allows the user to run arbitrary code 
with the same privilege level as the main OpenVPN process (OpenVPNConnect.exe).

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://openvpn.net/vpn-server-resources/openvpn-connect-for-windows-change-log/#release-notes-for-3-3-1-2222
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e38598e8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenVPN Connect 3.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3613");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openvpn:connect");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openvpn_connect_win_installed.nbin");
  script_require_keys("installed_sw/OpenVPN Connect");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'OpenVPN Connect');

constraints = [{'min_version': '3.2.0', 'fixed_version': '3.3.1'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
