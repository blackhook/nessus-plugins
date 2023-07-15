#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118089);
  script_version("1.6");
  script_cvs_date("Date: 2020/02/14");

  script_cve_id("CVE-2018-15974");

  script_name(english:"Adobe FrameMaker <= 14.0.0.361 (2017 Release) Privilege Escalation (APSB18-37)");
  script_summary(english:"Checks the FrameMaker version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe FrameMaker installed on the remote Windows host
is prior to 14.0.0.361 (2017 Release). It is, therefore, affected by a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/framemaker/apsb18-37.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe FrameMaker 15.0.0.0 (2019 Release) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15974");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:framemaker");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_framemaker_installed.nbin");
  script_require_keys("installed_sw/Adobe FrameMaker", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
app_info = vcf::get_app_info(app:"Adobe FrameMaker", win_local:TRUE);

# affected is <= 14.0.0.361 (2017 Release)
# fixed is 2019 Release (15.x)
constraints = [{"max_version":"14.0.0.361", "fixed_display":"2019 Release (15.x)"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
