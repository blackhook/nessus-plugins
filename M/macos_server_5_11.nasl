##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146823);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-9995");
  script_xref(name:"IAVA", value:"2020-A-0576-S");
  script_xref(name:"APPLE-SA", value:"HT211932");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2020-12-14-9");

  script_name(english:"macOS : macOS Server < 5.11 XSS (HT211932)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update for macOS Server.");
  script_set_attribute(attribute:"description", value:
"The version of macOS Server (formerly known as Mac OS X Server) installed on the remote host is prior to 5.11. It is,
therefore, affected by an open redirect or cross-site scripting (XSS) vulnerability due to an issue in the parsing of
URLs. An unauthenticated, remote attacker can exploit this, by convincing a user to click a specially crafted URL, to
execute arbitrary script code in a user's browser session.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT211932");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS Server version 5.11 or later. Note that macOS Server version 5.11 is available only for macOS 11
(Big Sur) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9995");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_server_services.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Server/Version");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item('Host/MacOSX/Version');
if (!os) audit(AUDIT_OS_NOT, 'macOS');

kb_ver = 'MacOSX/Server/Version';

app_info = vcf::get_app_info(app:'macOS Server', kb_ver:kb_ver);

constraints = [
  {'fixed_version': '5.11' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
