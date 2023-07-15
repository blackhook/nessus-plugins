##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148958);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/18");

  script_cve_id("CVE-2021-23886", "CVE-2021-23887");
  script_xref(name:"MCAFEE-SB", value:"SB10357");
  script_xref(name:"IAVA", value:"2021-A-0183-S");

  script_name(english:"McAfee DLPe Agent < 11.6.100.41 Multiple Vulnerabilities (SB10357)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the McAfee Data Loss Prevention Endpoint (DLPe) Agent installed on the remote Windows host is prior to
11.6.100.41. It is, therefore, affected by multiple vulnerabilities:

  - Denial of Service vulnerability in McAfee Data Loss Prevention (DLP) Endpoint for Windows prior to
    11.6.100.41 allows a local, low privileged, attacker to cause a BSoD through suspending a process,
    modifying the processes memory and restarting it. This is triggered by the hdlphook driver reading
    invalid memory. (CVE-2021-23886)

  - Privilege Escalation vulnerability in McAfee Data Loss Prevention (DLP) Endpoint for Windows prior to
    11.6.100.41 allows a local, low privileged, attacker to write to arbitrary controlled kernel addresses.
    This is achieved by launching applications, suspending them, modifying the memory and restarting them
    when they are monitored by McAfee DLP through the hdlphook driver. (CVE-2021-23887)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10357");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee DLPe 11.6.100.41 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23887");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:data_loss_prevention_endpoint");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_dlpe_agent_installed.nbin");
  script_require_keys("installed_sw/McAfee DLPe Agent", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'McAfee DLPe Agent', win_local:TRUE);

var constraints = [{ 'fixed_version':'11.6.100.41' }];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
