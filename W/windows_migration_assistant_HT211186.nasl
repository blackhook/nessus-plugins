##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141782);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-9858");
  script_xref(name:"APPLE-SA", value:"HT211186");
  script_xref(name:"IAVA", value:"2020-A-0227-S");

  script_name(english:"Windows Migration Assistant < 2.2.0.0 Arbitrary Code Execution (HT211186)");

  script_set_attribute(attribute:"synopsis", value:
"A Windows-to-Mac migration tool installed on the remote host is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Windows Migration Assistant installed on the remote
host is prior to 2.2.0.0. It is, therefore, affected by an arbitrary code execution vulnerability due to a dynamic
library loading issue. An unauthenticated, local attacker can exploit this, by running the installer in an untrusted
directory, to execute arbitrary code in the context of the current OS user.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT211186");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Windows Migration Assistant version 2.2.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9858");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:windows_migration_assistant");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("windows_migration_assistant_installed.nbin");
  script_require_keys("installed_sw/Windows Migration Assistant");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Windows Migration Assistant', win_local:TRUE);

constraints = [
  { 'fixed_version' : '2.2.0.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

