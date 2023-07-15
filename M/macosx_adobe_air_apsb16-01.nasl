#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(87658);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2015-8459",
    "CVE-2015-8460",
    "CVE-2015-8634",
    "CVE-2015-8635",
    "CVE-2015-8636",
    "CVE-2015-8638",
    "CVE-2015-8639",
    "CVE-2015-8640",
    "CVE-2015-8641",
    "CVE-2015-8642",
    "CVE-2015-8643",
    "CVE-2015-8644",
    "CVE-2015-8645",
    "CVE-2015-8646",
    "CVE-2015-8647",
    "CVE-2015-8648",
    "CVE-2015-8649",
    "CVE-2015-8650",
    "CVE-2015-8651",
    "CVE-2016-0959"
  );
  script_bugtraq_id(
    79700,
    79701,
    79704,
    79705
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"Adobe AIR for Mac <= 20.0.0.204 Multiple Vulnerabilities (APSB16-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe AIR installed on the remote Mac OS X host is
equal or prior to version 20.0.0.204. It is, therefore, affected by
multiple vulnerabilities :

  - A type confusion error exists that a remote attacker can
    exploit to execute arbitrary code. (CVE-2015-8644)

  - An integer overflow condition exists that a remote
    attacker can exploit to execute arbitrary code.
    (CVE-2015-8651)

  - Multiple use-after-free errors exist that a remote
    attacker can exploit to execute arbitrary code.
    (CVE-2015-8634, CVE-2015-8635, CVE-2015-8638,
    CVE-2015-8639, CVE-2015-8640, CVE-2015-8641,
    CVE-2015-8642, CVE-2015-8643, CVE-2015-8646,
    CVE-2015-8647, CVE-2015-8648, CVE-2015-8649,
    CVE-2015-8650, CVE-2016-0959)

  - Multiple memory corruption issues exist that allow a
    remote attacker to execute arbitrary code.
    (CVE-2015-8459, CVE-2015-8460, CVE-2015-8636,
    CVE-2015-8645)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-01.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe AIR version 20.0.0.233 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0959");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-8459");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
cutoff_version = '20.0.0.204';
fixed_version_for_report = '20.0.0.233';

if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
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
