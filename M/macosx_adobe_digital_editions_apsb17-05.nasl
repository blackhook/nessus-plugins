#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97215);
  script_version("1.6");
  script_cvs_date("Date: 2018/07/16 12:48:31");

  script_cve_id(
    "CVE-2017-2973",
    "CVE-2017-2974", 
    "CVE-2017-2975", 
    "CVE-2017-2976", 
    "CVE-2017-2977", 
    "CVE-2017-2978", 
    "CVE-2017-2979", 
    "CVE-2017-2980", 
    "CVE-2017-2981" 
  );
  script_bugtraq_id(
    96192,
    96195
  );

  script_name(english:"Adobe Digital Editions < 4.5.4 Multiple Vulnerabilities (APSB17-05) (macOS)");
  script_summary(english:"Checks the version of Adobe Digital Editions on Mac OS X.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Digital Editions installed on the remote macOS or
Mac OS X host is prior to 4.5.4. It is, therefore, affected by
multiple vulnerabilities :

  - A heap buffer overflow condition exists that allows
    an unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2017-2973).

  - Multiple buffer overflow conditions exist that allow an
    unauthenticated, remote attacker to disclose memory
    contents. (CVE-2017-2974, CVE-2017-2975, CVE-2017-2976,
    CVE-2017-2978, CVE-2017-2977, CVE-2017-2979,
    CVE-2017-2980, CVE-2017-2981)");
  # https://helpx.adobe.com/security/products/Digital-Editions/apsb17-05.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c2d48df");
  # http://www.adobe.com/solutions/ebook/digital-editions/release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3aa2f29");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Digital Editions version 4.5.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:digital_editions");
  script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("macosx_adobe_digital_editions_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Digital Editions");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");
get_kb_item_or_exit("Host/MacOSX/Version");

app_name = "Adobe Digital Editions";
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

ver_ui  = FALSE;
version = install['version'];
path    = install['path'];

if (!empty_or_null(install['display_version']))
  ver_ui  = install['display_version'];

fix = "4.5.4.0";

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0 )
{
  items = make_array("Path", path,
                     "Installed version", version,
                     "Fixed version", "4.5.4 (" + fix + ")");
  if (ver_ui)
    items["Installed version"] = version + " (" + ver_ui + ")";

  order = make_list("Path", "Installed version", "Fixed version");

  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

