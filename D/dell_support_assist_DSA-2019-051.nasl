#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137364);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2019-3718", "CVE-2019-3719");
  script_bugtraq_id(108020);

  script_name(english:"Dell SupportAssist Multiple Vulnerabilities (DSA-2019-051)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a Dell SupportAssist that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Dell SupportAssist Client versions prior to 3.2.0.90, installed on the remote Windows host reportedly 
is affected by multiple vulnerabilities :

  - An improper origin validation vulnerability exist in Dell SupportAssist Client versions prior to 3.2.0.90.
    An unauthenticated remote attacker could potentially exploit this vulnerability to attempt CSRF attacks 
    on users of the impacted systems. (CVE-2019-3718).

Dell SupportAssist Client versions prior to 3.2.0.90 contain a remote code execution vulnerability. 


  - A remote code execution vulnerability exist in Dell SupportAssist Client versions prior to 3.2.0.90.
    An unauthenticated attacker, sharing the network access layer with the vulnerable system, can compromise 
    the vulnerable system by tricking a victim user into downloading and executing arbitrary executables via 
    SupportAssist client from attacker hosted sites. (CVE-2019-3719).");
  # https://www.dell.com/support/article/en-ie/sln316857/dsa-2019-051-dell-supportassist-client-multiple-vulnerabilities?lang=en
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28b34214");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell SupportAssist Client version 3.2.0.90 and later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3719");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-3718");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:supportassist");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_supportassist_installed.nbin");
  script_require_keys("installed_sw/Dell SupportAssist");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Dell SupportAssist', win_local:TRUE);

constraints = [{'fixed_version':'3.2.0.90'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
