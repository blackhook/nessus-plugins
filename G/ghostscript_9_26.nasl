#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119240);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id(
    "CVE-2018-19134",
    "CVE-2018-19409",
    "CVE-2018-19475",
    "CVE-2018-19476",
    "CVE-2018-19477",
    "CVE-2018-19478"
  );
  script_bugtraq_id(105990);

  script_name(english:"Artifex Ghostscript < 9.26 PostScript Multiple Vulnerabilities");
  script_summary(english:"Checks the Ghostscript version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a library that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Artifex Ghostscript installed on the remote Windows
host is prior to 9.26. It is, therefore, affected by multiple 
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://ghostscript.com/doc/9.26/History9.htm");
  # https://semmle.com/news/semmle-discovers-severe-vulnerability-ghostscript-postscript-pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d10a2fe");
  script_set_attribute(attribute:"solution", value:
"Update to 9.26.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19409");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/28");

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
constraints = [{"fixed_version" : "9.26"}];

app_info = vcf::get_app_info(app:app, win_local:TRUE);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
