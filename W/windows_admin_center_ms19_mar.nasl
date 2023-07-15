#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(131835);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/11");

  script_cve_id("CVE-2019-0813");
  script_bugtraq_id(107682);
  script_xref(name:"MSKB", value:"4493552");
  script_xref(name:"MSFT", value:"MS19-4493552");

  script_name(english:"Security Update for Microsoft Windows Admin Center (March 2019)");
  script_summary(english:"Checks the version of Microsoft Admin Center");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is contains an application that is affected by an elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of Microsoft Windows Admin Center that is missing a security update. It is,
therefore, affected by an elevation of privilege vulnerability due to improper impersonating of operations in certain 
situations. An unauthenticated, remote attacker can exploit this issue to gain privileged or administrator access to the
system.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0813
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ee3d5b5");
  # https://support.microsoft.com/en-us/help/4493552/security-update-for-vulnerabilities-in-windows-admin-center
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ccad034c");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate update referenced in the Microsoft advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0813");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:windows_admin_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("windows_admin_center_installed.nbin");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

app = 'Windows Admin Center';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'fixed_version' : '1.1.1903.26001' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
