#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(146479);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/17");

  script_cve_id("CVE-2021-1728");
  script_xref(name:"MSKB", value:"4601269");
  script_xref(name:"MSFT", value:"MS21-4601269");
  script_xref(name:"IAVA", value:"2021-A-0089");

  script_name(english:"Security Updates for Microsoft System Center Operations Manager (February 2021)");

  script_set_attribute(attribute:"synopsis", value:
"A web application hosted on the remote Windows system is affected by an elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft System Center Operations Manager installed on the remote Windows host is affected by an
elevation of privilege vulnerability. A remote, authenticated attacker can exploit this vulnerability by sending a
specially crafted request to an affected SCOM instance.");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-1728
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86b40c69");
  # https://support.microsoft.com/en-us/topic/update-for-event-log-channel-in-system-center-operations-manager-2019-kb4601269-19bfccbe-dbda-1371-9871-f2a32157028a
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d57fb2a");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for System Center Operations Manager 2019.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1728");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:system_center_operations_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("system_center_operations_mgr_installed.nasl");
  script_require_keys("installed_sw/System Center Operations Manager Server");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'System Center Operations Manager Server', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version':'10.19.10050.0', 'fixed_version':'10.19.10457.0' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

