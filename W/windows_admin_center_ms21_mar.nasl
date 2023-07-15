##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147420);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/11");

  script_cve_id("CVE-2021-27066");

  script_name(english:"Security Update for Microsoft Windows Admin Center (March 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is contains an application that is affected by a security feature bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of Microsoft Windows Admin Center that is missing a security update. It is,
therefore, affected by a security feature bypass vulnerability. An authenticated, remote attacker can exploit this to
bypass security features.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-27066");
  # https://techcommunity.microsoft.com/t5/windows-admin-center-blog/windows-admin-center-version-2103-is-now-generally-available/ba-p/2176438
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0fbee7f5");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate update referenced in the Microsoft advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27066");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_admin_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("windows_admin_center_installed.nbin");
  script_require_keys("installed_sw/Windows Admin Center");

  exit(0);
}

include('vcf.inc');

app = 'Windows Admin Center';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'fixed_version' : '1.3.2103.1006' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
