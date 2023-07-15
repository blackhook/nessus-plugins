#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171189);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/10");

  script_cve_id(
    "CVE-2020-6917",
    "CVE-2020-6918",
    "CVE-2020-6919",
    "CVE-2020-6920",
    "CVE-2020-6921",
    "CVE-2020-6922",
    "CVE-2022-23453",
    "CVE-2022-23455",
    "CVE-2022-23456"
  );
  script_xref(name:"HP", value:"HPSBGN03762");
  script_xref(name:"IAVB", value:"2023-B-0005");

  script_name(english:"HP Support Assistant < 9.11 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP Support Assistant installed on the remote host is affected by a vulnerability as referenced in the
HPSBGN03762 advisory.

  - Potential security vulnerabilities including compromise of integrity, and allowed communication with untrusted
    clients has been identified in HP Support Assistant software. (CVE-2020-6917, CVE-2020-6918, CVE-2020-6919)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.hp.com/us-en/document/ish_5585999-5586023-16
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e42114fa");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Support Assistant version 9.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6922");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-23455");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:support_assistant");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_support_assistant_installed.nbin");
  script_require_keys("installed_sw/HP Support Assistant");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'HP Support Assistant');
constraints = [{ 'fixed_version' : '9.11' }];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
