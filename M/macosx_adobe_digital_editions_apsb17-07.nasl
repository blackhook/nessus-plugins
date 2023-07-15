#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100793);
  script_version("1.6");
  script_cvs_date("Date: 2018/07/16 12:48:31");

  script_cve_id(
    "CVE-2017-3088",
    "CVE-2017-3089",
    "CVE-2017-3090",
    "CVE-2017-3092",
    "CVE-2017-3093",
    "CVE-2017-3094",
    "CVE-2017-3095",
    "CVE-2017-3096",
    "CVE-2017-3097"
  );
  script_bugtraq_id(
    99020,
    99021,
    99024
  );

  script_name(english:"Adobe Digital Editions < 4.5.5 Multiple Vulnerabilities (APSB17-20) (macOS)");
  script_summary(english:"Checks the version of Adobe Digital Editions on Mac OS X.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Digital Editions installed on the remote macOS or
Mac OS X host is prior to 4.5.5. It is, therefore, affected by
multiple vulnerabilities :

  - Multiple memory corruption issues exist due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit these to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2017-3088, CVE-2017-3089, CVE-2017-3093,
    CVE-2017-3096)

  - Multiple unspecified flaws exist related to insecure
    loading of libraries. A local attacker can exploit these
    to gain elevated privileges. (CVE-2017-3090,
    CVE-2017-3092, CVE-2017-3097)

  - Multiple stack-based buffer overflow conditions exist
    due to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit these to
    disclose memory contents. (CVE-2017-3094, CVE-2017-3095)");
  # https://helpx.adobe.com/security/products/Digital-Editions/apsb17-20.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?344c096d");
  # http://www.adobe.com/solutions/ebook/digital-editions/release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3aa2f29");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Digital Editions version 4.5.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/14");

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
  { "fixed_version" : "4.5.5" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
