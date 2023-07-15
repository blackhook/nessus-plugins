#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164640);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2021-38402", "CVE-2021-38404", "CVE-2021-38406");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/15");

  script_name(english:"Delta DOPSoft <= 2.00.07 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Delta DOPSoft installed on the remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Delta DOPSoft installed on the remote host is prior to or equal to 2.00.07. It is, therefore, affected
by multiple vulnerabilities as referenced in the CISA ICSA-21-252-02 advisory.

  - Delta Electronic DOPSoft 2 (Version 2.00.07 and prior) lacks proper validation of user-supplied data when
    parsing specific project files. This could lead to a stack-based buffer overflow while trying to copy to a
    buffer during font string handling. An attacker could leverage this vulnerability to execute code in the
    context of the current process. (CVE-2021-38402)

  - Delta Electronic DOPSoft 2 (Version 2.00.07 and prior) lacks proper validation of user-supplied data when
    parsing specific project files. This could result in a heap-based buffer overflow. An attacker could
    leverage this vulnerability to execute code in the context of the current process. (CVE-2021-38404)

  - Delta Electronic DOPSoft 2 (Version 2.00.07 and prior) lacks proper validation of user-supplied data when
    parsing specific project files. This could result in multiple out-of-bounds write instances. An attacker
    could leverage this vulnerability to execute code in the context of the current process. (CVE-2021-38406)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cisa.gov/uscert/ics/advisories/icsa-21-252-02");
  script_set_attribute(attribute:"solution", value:
"DOPSoft 2 will not receive an update to mitigate these vulnerabilities because it is an end-of-life product.
Delta Electronics recommends users to switch to the replacement software when available.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38406");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:deltaww:dopsoft");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("delta_dopsoft_win_installed.nbin");
  script_require_keys("installed_sw/Delta DOPSoft");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Delta DOPSoft', win_local:TRUE);

app_info.display_version = app_info.version + " (file version)";

# After installing the package DELTA_IA-HMI_DOPSoft-2-00-07-04_SW_TC-SC-EN-SP_20171214,
# Files are installed to C:\Program Files (x86)\Delta Industrial Automation\DOPSoft 2.00.07\
# and the DOPSoft.exe has a file version of 4.0.7.4 (not 2.x)
# 2.00.07 file version is 4.0.7.4
var constraints = [
  { 'max_version': '4.0.7.4', 'fixed_display':'See ICSA-21-252-02 advisory or contact Delta.' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
