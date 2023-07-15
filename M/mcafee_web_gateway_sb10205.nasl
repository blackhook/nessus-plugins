#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102496);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_cve_id(
    "CVE-2012-6706",
    "CVE-2017-1000364",
    "CVE-2017-1000366",
    "CVE-2017-1000368"
  );
  script_xref(name:"MCAFEE-SB", value:"SB10205");

  script_name(english:"McAfee Web Gateway 7.6.x < 7.6.2.15 / 7.7.x < 7.7.2.3 Multiple Vulnerabilities (SB10205)");
  script_summary(english:"Checks the version of McAfee Web Gateway.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host running McAfee Web Gateway is affected by multiple
code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of McAfee Web Gateway (MWG) that
is affected by multiple security vulnerabilities :

  - A memory corruption flaw exists in unrar before 5.5.5, as used in
    Sophos Anti-Virus Threat Detection Engine before 3.37.2 and other
    products that allows remote attackers to execute arbitrary code.
    (CVE-2012-6706)

  - A memory corruption flaw exists in Linux Kernel versions 4.11.5
    and earlier that allows remote attacks to execute arbitrary code
    with elevated privileges.(CVE-2017-1000364)

  - A memory corruption flaw exists in the handling of LD_LIBRARY_PATH
    that allows a remote attacker to manipulate the heap/stack that
    may lead to arbitrary code execution. This issue only affects GNU
    glibc 2.25 and prior. (CVE-2017-1000366)

  - An input validation flaw exists in Todd Miller's sudo version
    1.8.20p1 and earlier that results in information disclosure and
    arbitrary command execution. (CVE-2017-1000368)");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10205");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee
  Web Gateway 7.6.2.15 / 7.7.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-6706");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Solaris RSH Stack Clash Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:web_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_web_gateway_detect.nbin");
  script_require_keys("Host/McAfee Web Gateway/Version", "Host/McAfee Web Gateway/Display Version");

  exit(0);
}

include("vcf.inc");

app_info = vcf::combined_get_app_info(app:"McAfee Web Gateway");

vcf::check_granularity(app_info:app_info, sig_segments:4);

constraints = [
  { "min_version" : "7.6", "max_version" : "7.6.2.14", "fixed_version" : "7.6.2.15" },
  { "min_version" : "7.7", "max_version" : "7.7.2.2", "fixed_version" : "7.7.2.3" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
