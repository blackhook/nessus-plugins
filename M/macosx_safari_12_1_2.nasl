#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128178);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/29");

  script_cve_id(
    "CVE-2019-8644",
    "CVE-2019-8649",
    "CVE-2019-8658",
    "CVE-2019-8666",
    "CVE-2019-8669",
    "CVE-2019-8670",
    "CVE-2019-8671",
    "CVE-2019-8672",
    "CVE-2019-8673",
    "CVE-2019-8676",
    "CVE-2019-8677",
    "CVE-2019-8678",
    "CVE-2019-8679",
    "CVE-2019-8680",
    "CVE-2019-8681",
    "CVE-2019-8683",
    "CVE-2019-8684",
    "CVE-2019-8685",
    "CVE-2019-8686",
    "CVE-2019-8687",
    "CVE-2019-8688",
    "CVE-2019-8689",
    "CVE-2019-8690"
  );
  script_bugtraq_id(109327, 109328, 109329);

  script_name(english:"macOS : Apple Safari < 12.1.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the Safari version.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote macOS or Mac OS X
host is prior to 12.1.2 It is, therefore, affected by multiple
vulnerabilities in the following components :

  - Safari
  - WebKit");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT210355");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari version 12.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8644");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_apple_safari_installed.nbin");
  script_require_keys("Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

os = get_kb_item_or_exit('Host/MacOSX/Version');

if (!preg(pattern:"Mac OS X 10\.(12|13|14)([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, 'macOS Sierra 10.12 / macOS High Sierra 10.13 / macOS Mojave 10.14');

installed = get_kb_item_or_exit('MacOSX/Safari/Installed', exit_code:0);
path      = get_kb_item_or_exit('MacOSX/Safari/Path', exit_code:1);
version   = get_kb_item_or_exit('MacOSX/Safari/Version', exit_code:1);

fixed_version = '12.1.2';

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  report = report_items_str(
    report_items:make_array(
      'Path', path,
      'Installed version', version,
      'Fixed version', fixed_version
    ),
    ordered_fields:make_list('Path', 'Installed version', 'Fixed version')
  );
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report, xss:TRUE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Safari', version, path);
