#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73434);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/26");

  script_cve_id(
    "CVE-2014-0506",
    "CVE-2014-0507",
    "CVE-2014-0508",
    "CVE-2014-0509"
  );
  script_bugtraq_id(
    66208,
    66699,
    66701,
    66703
  );

  script_name(english:"Adobe AIR for Mac <= 4.0.0.1628 Multiple Vulnerabilities (APSB14-09)");
  script_summary(english:"Checks version gathered by local check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a version of Adobe AIR that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of Adobe AIR on the remote Mac
OS X host is 4.0.0.1628 or earlier. It is, therefore, reportedly
affected by the following vulnerabilities :

  - A use-after-free error exists that could lead to
    arbitrary code execution. (CVE-2014-0506)

  - A buffer overflow error exists that could lead to
    arbitrary code execution. (CVE-2014-0507)

  - An unspecified error exists that could allow a security
    bypass leading to information disclosure.
    (CVE-2014-0508)

  - An unspecified error exists that could allow cross-
    site scripting attacks. (CVE-2014-0509)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb14-09.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe AIR 13.0.0.83 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0506");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_air_installed.nasl");
  script_require_keys("MacOSX/Adobe_AIR/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


kb_base = "MacOSX/Adobe_AIR";
version = get_kb_item_or_exit(kb_base+"/Version");
path = get_kb_item_or_exit(kb_base+"/Path");

# nb: we're checking for versions less than *or equal to* the cutoff!
cutoff_version = '4.0.0.1628';
fixed_version_for_report = '13.0.0.83';

if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{

  # XSS
  set_kb_item(name:'www/0/XSS', value: TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version_for_report +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe AIR", version, path);
