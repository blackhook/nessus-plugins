#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122254);
  script_version("1.3");
  script_cvs_date("Date: 2019/10/31 15:18:52");

  script_cve_id("CVE-2019-7093");

  script_name(english:"Adobe Creative Cloud Desktop <= 4.7.0.400 Privilege Escalation Vulnerability (APSB19-11)");
  script_summary(english:"Checks the version of Creative Cloud.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Creative Cloud Desktop installed on the remote
Windows host is equal or prior to 4.7.0.400. It is, therefore,
affected by a privilege escalation vulnerability
as noted in the APSB19-11 advisory.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://helpx.adobe.com/security/products/creative-cloud/apsb19-11.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f7a8451");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Creative Cloud Desktop version 4.8.0.410 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7093");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:creative_cloud");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_creative_cloud_installed.nbin");
  script_require_keys("installed_sw/Adobe Creative Cloud");

  exit(0);
}

include("http.inc");
include("vcf.inc");

app = "Adobe Creative Cloud";

app_info = vcf::get_app_info(app:app);

constraints = [
  { "max_version" : "4.7.0.400", "fixed_version" : "4.8.0.410" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
