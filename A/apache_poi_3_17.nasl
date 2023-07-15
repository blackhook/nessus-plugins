#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106717);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2017-12626");
  script_bugtraq_id(102879);
  script_xref(name:"IAVB", value:"2018-B-0019-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Apache POI < 3.17 Multiple DoS Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of Apache POI installed on the remote host is affected by multiple DoS vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache POI installed on the remote host is a version prior to 3.17. It is, therefore, affected by
multiple DoS vulnerabilities.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"http://poi.apache.org/changes.html#3.17");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache POI 3.17 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12626");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:poi");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_poi_detect.nbin");
  script_require_keys("installed_sw/Apache POI");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

app_info = vcf::get_app_info(app:"Apache POI");

constraints = [{ "fixed_version" : "3.17" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
