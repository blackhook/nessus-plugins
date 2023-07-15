#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106397);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2018-4088", "CVE-2018-4096");
  script_bugtraq_id(102775);

  script_name(english:"Apple iTunes < 12.7.3 WebKit Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks the version of iTunes on Windows.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is
prior to 12.7.3. It is, therefore, affected by multiple vulnerabilities 
in webkit as referenced in the HT208474 advisory.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208474");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4096");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("installed_sw/iTunes Version", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

# Ensure this is Windows
get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"iTunes Version", win_local:TRUE);

constraints = [{"fixed_version" : "12.7.3"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
