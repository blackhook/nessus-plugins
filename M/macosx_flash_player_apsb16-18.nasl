#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91671);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/28");

  script_cve_id(
    "CVE-2016-4122",
    "CVE-2016-4123",
    "CVE-2016-4124",
    "CVE-2016-4125",
    "CVE-2016-4127",
    "CVE-2016-4128",
    "CVE-2016-4129",
    "CVE-2016-4130",
    "CVE-2016-4131",
    "CVE-2016-4132",
    "CVE-2016-4133",
    "CVE-2016-4134",
    "CVE-2016-4135",
    "CVE-2016-4136",
    "CVE-2016-4137",
    "CVE-2016-4138",
    "CVE-2016-4139",
    "CVE-2016-4140",
    "CVE-2016-4141",
    "CVE-2016-4142",
    "CVE-2016-4143",
    "CVE-2016-4144",
    "CVE-2016-4145",
    "CVE-2016-4146",
    "CVE-2016-4147",
    "CVE-2016-4148",
    "CVE-2016-4149",
    "CVE-2016-4150",
    "CVE-2016-4151",
    "CVE-2016-4152",
    "CVE-2016-4153",
    "CVE-2016-4154",
    "CVE-2016-4155",
    "CVE-2016-4156",
    "CVE-2016-4166",
    "CVE-2016-4171"
  );
  script_xref(name:"CERT", value:"748992");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");

  script_name(english:"Adobe Flash Player for Mac <= 21.0.0.242 Multiple Vulnerabilities (APSB16-18)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Mac OS X
host is equal or prior to version 21.0.0.242. It is, therefore,
affected by multiple vulnerabilities :

  - Multiple memory corruption issues exist that allow an
    unauthenticated, remote attacker to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2016-4122, CVE-2016-4123, CVE-2016-4124,
    CVE-2016-4125, CVE-2016-4127, CVE-2016-4128,
    CVE-2016-4129, CVE-2016-4130, CVE-2016-4131,
    CVE-2016-4132, CVE-2016-4133, CVE-2016-4134,
    CVE-2016-4137, CVE-2016-4141, CVE-2016-4150,
    CVE-2016-4151, CVE-2016-4152, CVE-2016-4153,
    CVE-2016-4154, CVE-2016-4155, CVE-2016-4156,
    CVE-2016-4166, CVE-2016-4171)

  - Multiple heap buffer overflow conditions exist due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit these to
    execute arbitrary code. (CVE-2016-4135, CVE-2016-4136,
    CVE-2016-4138).

  - An unspecified vulnerability exists that allows an
    unauthenticated, remote attacker to bypass the
    same-origin policy, resulting in the disclosure of
    potentially sensitive information. (CVE-2016-4139)

  - An unspecified flaw exists when loading certain dynamic
    link libraries due to using a search path that includes
    directories which may not be trusted or under the user's
    control. An unauthenticated, remote attacker can exploit
    this, by inserting a specially crafted library in the
    path, to execute arbitrary code in the context of the
    user. (CVE-2016-4140)

  - Multiple use-after-free errors exist that allow an
    unauthenticated, remote attacker to deference already
    freed memory, resulting in the execution of arbitrary
    code. (CVE-2016-4142, CVE-2016-4143, CVE-2016-4145,
    CVE-2016-4146, CVE-2016-4147, CVE-2016-4148)

  - Multiple type confusion errors exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-4144, CVE-2016-4149)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-18.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 22.0.0.192 or later.

Alternatively, Adobe has made version 18.0.0.360 available for those
installations that cannot be upgraded to the latest version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4171");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");
path = get_kb_item_or_exit("MacOSX/Flash_Player/Path");

if (ver_compare(ver:version, fix:"19.0.0.0", strict:FALSE) >= 0)
{
  cutoff_version = "21.0.0.242";
  fix = "22.0.0.192";
}
else
{
  cutoff_version = "18.0.0.352";
  fix = "18.0.0.360";
}

# we're checking for versions less than or equal to the cutoff!
if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Flash Player for Mac", version, path);
