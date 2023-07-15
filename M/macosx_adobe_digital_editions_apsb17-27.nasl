#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102325);
  script_version("1.5");
  script_cvs_date("Date: 2018/07/14  1:59:37");

  script_cve_id(
    "CVE-2017-3091",
    "CVE-2017-11272",
    "CVE-2017-11274",
    "CVE-2017-11275",
    "CVE-2017-11276",
    "CVE-2017-11277",
    "CVE-2017-11278",
    "CVE-2017-11279",
    "CVE-2017-11280"
  );

  script_name(english:"Adobe Digital Editions < 4.5.6 Multiple Vulnerabilities (APSB17-27) (macOS)");
  script_summary(english:"Checks the version of Adobe Digital Editions on Mac OS X.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Digital Editions installed on the remote macOS
or Mac OS X host is prior to 4.5.6. It is, therefore, affected by
multiple vulnerabilities :

  - An XML external entity (XXE) parsing flaw exists that can lead to
    information disclosure. (CVE-2017-11272)

  - An unspecified buffer overflow vulnerability may result in the
    execution of arbitrary code. (CVE-2017-11274)

  - Multiple unspecified memory corruption flaws exist that can cause
    a memory address disclosure. (CVE-2017-3091, CVE-2017-11275,
    CVE-2017-11276, CVE-2017-11277, CVE-2017-11278, CVE-2017-11279,
    CVE-2017-11280)");
  # https://helpx.adobe.com/security/products/Digital-Editions/apsb17-27.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79c395bc");
  # http://www.adobe.com/solutions/ebook/digital-editions/release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3aa2f29");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Digital Editions version 4.5.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/09");

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


include("vcf.inc");

get_kb_item_or_exit("Host/MacOSX/Version");
get_kb_item_or_exit("Host/local_checks_enabled");

app_info = vcf::get_app_info(app:"Adobe Digital Editions");

constraints = [
  { "fixed_version" : "4.5.6" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
