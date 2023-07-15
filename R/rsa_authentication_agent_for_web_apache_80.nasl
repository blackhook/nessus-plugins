#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105413);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2017-14377");
  script_bugtraq_id(101980);

  script_name(english:"RSA Authentication Agent for Web for Apache 8.x < 8.0.1 Build 618 Filter Bypass");
  script_summary(english:"Checks version of RSA Authentication Agent for Web for Apache");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an authentication agent installed that is
affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of RSA Authentication Agent for Web for Apache is 8.x
prior to 8.0.1 Build 618. It is, therefore, potentially affected by
an unspecified authentication bypass vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2017/Nov/46");
  script_set_attribute(attribute:"solution", value:
"Upgrade to RSA Authentication Agent for Web for Apache 8.0.1
Build 618 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14377");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rsa:authentication_agent_for_web");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("rsa_authentication_agent_for_web_apache_detect.nbin");
  script_require_keys("installed_sw/RSA Authentication Agent for Web for Apache", "Settings/ParanoidReport");

  exit(0);
}

include("vcf.inc");

app = "RSA Authentication Agent for Web for Apache";

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

# Per https://seclists.org/fulldisclosure/2017/Nov/46
#Affected Products:
#  RSA(r) Authentication Agent for Web: Apache Web Server version 8.0
#  RSA(r) Authentication Agent for Web: Apache Web Server version 8.0.1 prior to Build 618
constraints = [
  { "min_version" : "8.0", "fixed_version" : "8.0.1.618" }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
