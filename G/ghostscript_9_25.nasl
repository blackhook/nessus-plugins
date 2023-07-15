#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117596);
  script_version("1.4");
  script_cvs_date("Date: 2019/04/05 23:25:09");

  script_cve_id(
    "CVE-2018-16509",
    "CVE-2018-16802"
  );

  script_name(english:"Artifex Ghostscript < 9.25 PostScript Code Execution Vulnerability");
  script_summary(english:"Checks the Ghostscript version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a library that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Artifex Ghostscript installed on the remote Windows
host is prior to 9.25. It is, therefore, affected by a code 
execution vulnerability.");
  script_set_attribute(attribute:"see_also", value: "https://ghostscript.com/doc/9.25/History9.htm");
  script_set_attribute(attribute:"solution", value: "Update to 9.25.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16802");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ghostscript Failed Restore Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/19");

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
constraints = [{"fixed_version" : "9.25"}];

app_info = vcf::get_app_info(app:app, win_local:TRUE);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
