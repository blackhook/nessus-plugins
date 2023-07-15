#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139727);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/08");

  script_cve_id("CVE-2020-11008");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2020-05-19");
  script_xref(name:"APPLE-SA", value:"HT211183");

  script_name(english:"Apple Xcode < 11.5 Git Credentials Disclosure (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"An IDE application installed on the remote macOS or Mac OS X host is affected by a credentials disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Xcode installed on the remote macOS or Mac OS X host is prior to 11.5. It is, therefore, affected
by an information disclosure vulnerability whereby Git can be tricked into sending private credentials to a host
controlled by an attacker. An attacker can exploit this vulnerability by persuading a victim to open a crafted
malicious `git clone` URL.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT211183");
  # https://lists.apple.com/archives/security-announce/2020/May/msg00000.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?748cd761");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Xcode version 11.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11008");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:xcode");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_xcode_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Apple Xcode");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os))
  audit(AUDIT_OS_NOT, 'macOS or Mac OS X');

app_info = vcf::get_app_info(app:'Apple Xcode');

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'fixed_version' : '11.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

