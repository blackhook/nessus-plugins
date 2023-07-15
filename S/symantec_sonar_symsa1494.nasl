#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130630);
  script_version("1.2");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2019-12752");
  script_bugtraq_id(110611);
  script_xref(name:"IAVA", value:"2019-A-0408");

  script_name(english:"Symantec SONAR < 12.0.2 Security Bypass (SYMSA1494)");
  script_summary(english:"Checks the SEP Client version.");

  script_set_attribute(attribute:"synopsis", value:
"The Symantec SONAR installed on the remote host is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec SONAR installed on the remote host is prior to 12.0.2. It is, therefore, affected by a security
bypass vulnerability due to a flaw the tamper protection. An authenticated attacker can exploit this, to circumvent
tamper protection on the resident system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.symantec.com/us/en/article.symsa1494.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87206b0c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec SONAR version 12.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12752");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:sonar");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("savce_installed.nasl");
  script_require_keys("installed_sw/Symantec SONAR");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Symantec SONAR');

constraints = [{ 'fixed_version' : '12.0.2' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
