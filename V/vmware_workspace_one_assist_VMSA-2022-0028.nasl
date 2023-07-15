#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167615);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/17");

  script_cve_id(
    "CVE-2022-31685",
    "CVE-2022-31686",
    "CVE-2022-31687",
    "CVE-2022-31688",
    "CVE-2022-31689"
  );
  script_xref(name:"VMSA", value:"VMSA-2022-0028");
  script_xref(name:"IAVA", value:"2022-A-0483");

  script_name(english:"VMware Workspace One Assist Multiple Vulnerabilities (VMSA-2022-0028)");

  script_set_attribute(attribute:"synopsis", value:
"The VMWare Workspace One Assist server running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The VMware Workspace One Assist server running on the remote host is affected multiple vulnerabilities, including the
following:

  - VMware Workspace ONE Assist prior to 22.10 contains an Authentication Bypass vulnerability. A malicious
    actor with network access to Workspace ONE Assist may be able to obtain administrative access without the
    need to authenticate to the application. (CVE-2022-31685)

  - VMware Workspace ONE Assist prior to 22.10 contains a Broken Authentication Method vulnerability. A
    malicious actor with network access to Workspace ONE Assist may be able to obtain administrative access
    without the need to authenticate to the application. (CVE-2022-31686)

  - VMware Workspace ONE Assist prior to 22.10 contains a Broken Access Control vulnerability. A malicious
    actor with network access to Workspace ONE Assist may be able to obtain administrative access without the
    need to authenticate to the application. (CVE-2022-31687)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0028.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 22.10 as per the VMSA-2022-0028 advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31685");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-31689");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:workspace_one_assist");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workspace_one_assist_web_detect.nbin");
  script_require_keys("installed_sw/VMware Workspace ONE Assist");

  exit(0);
}

include('vcf.inc');

var app = 'VMware Workspace ONE Assist';

var app_info = vcf::combined_get_app_info(app:app);

var constraints = [
  { 'min_version':'21.0', 'fixed_version':'22.10'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
