#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130273);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/05");

  script_cve_id(
    "CVE-2018-18073",
    "CVE-2019-10216",
    "CVE-2019-14811",
    "CVE-2019-14813",
    "CVE-2019-14817"
  );
  script_xref(name:"IAVB", value:"2019-B-0081-S");

  script_name(english:"Artifex Ghostscript < 9.50 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a library that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Artifex Ghostscript installed on the remote Windows host is
prior to 9.50. It is, therefore, affected by multiple security bypass
vulnerabilities. An attacker could exploit one of these vulnerabilities to gain
access to the file system and execute arbitrary commands.");
  script_set_attribute(attribute:"see_also", value:"https://www.ghostscript.com/Ghostscript_9.50.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Artifex Ghostscript 9.50 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14813");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artifex:ghostscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artifex:gpl_ghostscript");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ghostscript_detect.nbin");
  script_require_keys("installed_sw/Ghostscript");

  exit(0);
}

include("vcf.inc");

app = "Ghostscript";

constraints = [{"fixed_version" : "9.50"}];

app_info = vcf::get_app_info(app:app, win_local:TRUE);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
