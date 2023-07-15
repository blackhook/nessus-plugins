#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117459);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id(
    "CVE-2018-15908",
    "CVE-2018-15909",
    "CVE-2018-15910",
    "CVE-2018-15911",
    "CVE-2018-16511",
    "CVE-2018-16513",
    "CVE-2018-16539",
    "CVE-2018-16540",
    "CVE-2018-16541",
    "CVE-2018-16542",
    "CVE-2018-16543",
    "CVE-2018-16585"
  );

  script_name(english:"Artifex Ghostscript Multiple Vulnerabilities");
  script_summary(english:"Checks the Ghostscript version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a library that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Artifex Ghostscript installed on the remote Windows
host is prior to 9.24. It is, therefore, affected by multiple 
vulnerabilities due to improperly handling PostScript data. A
context-dependent attacker could cause a buffer overflow,
potentially crashing the service.");
  script_set_attribute(attribute:"see_also", value:"https://ghostscript.com/doc/9.24/History9.htm");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2018/dsa-4288");
  script_set_attribute(attribute:"see_also", value:"https://www.artifex.com/news/ghostscript-security-resolved/");
  script_set_attribute(attribute:"see_also", value:"https://bugs.chromium.org/p/project-zero/issues/detail?id=1640");
  script_set_attribute(attribute:"see_also", value:"https://bugs.ghostscript.com/show_bug.cgi?id=699654");
  script_set_attribute(attribute:"solution", value:
"Update to 9.24.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16585");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artifex:ghostscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artifex:gpl_ghostscript");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ghostscript_detect.nbin");
  script_require_keys("installed_sw/Ghostscript");

  exit(0);
}

include("vcf.inc");

app = "Ghostscript";
constraints = [{"fixed_version" : "9.24"}];

app_info = vcf::get_app_info(app:app, win_local:TRUE);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
