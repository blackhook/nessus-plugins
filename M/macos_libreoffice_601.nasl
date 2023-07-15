#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(122587);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/23");

  script_cve_id("CVE-2018-6871", "CVE-2018-10119");

  script_name(english:"LibreOffice < 5.4.5 or 6.x < 6.0.1 Multiple Vulnerabilities (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by an
arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of LibreOffice installed on the remote macOS host is
either 5.x prior to 5.4.5 or 6.x prior to 6.0.1. It is, therefore,
affected by the following vulnerabilities:

  - An arbitrary file read vulnerability exists in the
    COM.MICROSOFT.WEBSERVICE function due to improper
    validation of a URL input. An unauthenticated, remote
    attacker can exploit this, via a specially crafted file,
    to read arbitrary files and disclose sensitive information.
    (CVE-2018-6871)

  - A use after free vulnerability exists in the StgSmallStrm
    class due to the use of a short data type. An unauthenticated,
    remote attacker can exploit this, via a specially crafted
    file that uses the structured storage ole2 wrapper, to
    execute arbitrary code. (CVE-2018-10119)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2018-6871/");
  script_set_attribute(attribute:"see_also", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2018-10119/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LibreOffice version 5.4.5, 6.0.1 and later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10119");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-6871");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_libreoffice_installed.nasl");
  script_require_keys("installed_sw/LibreOffice", "Host/MacOSX/Version");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("Host/MacOSX/Version");
app_info = vcf::get_app_info(app:"LibreOffice");

constraints = [
  {"fixed_version" : "5.4.5"},
  {"min_version" : "6.0", "fixed_version" : "6.0.1"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
