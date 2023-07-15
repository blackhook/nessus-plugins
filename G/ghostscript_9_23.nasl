#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109405);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2018-10194");

  script_name(english:"Artifex Ghostscript PostScript Handling Buffer Overflow DoS");
  script_summary(english:"Checks the Ghostscript version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a library that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Artifex Ghostscript installed on the remote Windows
host is 9.22 or earlier. It is, therefore, affected by a denial of
service vulnerability due to improperly handling PostScript data. A
context-dependent attacker could cause a buffer overflow,
potentially crashing the service.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/oss-sec/2018/q2/58");
  script_set_attribute(attribute:"see_also", value:"https://bugs.ghostscript.com/show_bug.cgi?id=699255");
  # http://git.ghostscript.com/?p=ghostpdl.git;a=commit;h=39b1e54b2968620723bf32e96764c88797714879
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3f6a0f5");
  script_set_attribute(attribute:"solution", value:
"Update to 9.23 or refer to bug 699255 for possible workarounds or
patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10194");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artifex:ghostscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artifex:gpl_ghostscript");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ghostscript_detect.nbin");
  script_require_keys("installed_sw/Ghostscript");

  exit(0);
}

include("vcf.inc");

app = "Ghostscript";
constraints = [{"fixed_version" : "9.23"}];

app_info = vcf::get_app_info(app:app, win_local:TRUE);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
