#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164559);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id(
    "CVE-2020-25709",
    "CVE-2020-25710",
    "CVE-2021-4034",
    "CVE-2021-21996",
    "CVE-2021-45417",
    "CVE-2022-24407"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/18");

  script_name(english:"Nutanix AHV : Multiple Vulnerabilities (NXSA-AHV-20201105.30281)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AHV host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AHV installed on the remote host is prior to 20201105.30281. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AHV-20201105.30281 advisory.

  - A flaw was found in OpenLDAP. This flaw allows an attacker who can send a malicious packet to be processed
    by OpenLDAP's slapd server, to trigger an assertion failure. The highest threat from this vulnerability is
    to system availability. (CVE-2020-25709)

  - A flaw was found in OpenLDAP in versions before 2.4.56. This flaw allows an attacker who sends a malicious
    packet processed by OpenLDAP to force a failed assertion in csnNormalize23(). The highest threat from this
    vulnerability is to system availability. (CVE-2020-25710)

  - An issue was discovered in SaltStack Salt before 3003.3. A user who has control of the source, and
    source_hash URLs can gain full file system access as root on a salt minion. (CVE-2021-21996)

  - A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is
    a setuid tool designed to allow unprivileged users to run commands as privileged users according
    predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly
    and ends trying to execute environment variables as commands. An attacker can leverage this by crafting
    environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully
    executed the attack can cause a local privilege escalation given unprivileged users administrative rights
    on the target machine. (CVE-2021-4034)

  - AIDE before 0.17.4 allows local users to obtain root privileges via crafted file metadata (such as XFS
    extended attributes or tmpfs ACLs), because of a heap-based buffer overflow. (CVE-2021-45417)

  - In Cyrus SASL 2.1.17 through 2.1.27 before 2.1.28, plugins/sql.c does not escape the password for a SQL
    INSERT or UPDATE statement. (CVE-2022-24407)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AHV-20201105.30281
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e078b29");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AHV software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45417");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-24407");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Local Privilege Escalation in polkits pkexec');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:ahv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/Node/Version", "Host/Nutanix/Data/Node/Type");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info(node:TRUE);

var constraints = [
  { 'fixed_version' : '20201105.30281', 'product' : 'AHV', 'fixed_display' : 'Upgrade the AHV install to 20201105.30281 or higher.' }
];

vcf::nutanix::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
