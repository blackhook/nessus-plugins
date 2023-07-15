#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154167);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/22");

  script_cve_id("CVE-2021-30245");
  script_xref(name:"IAVA", value:"2021-A-0457-S");

  script_name(english:"Apache OpenOffice < 4.1.10 Arbitrary Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache OpenOffice installed on the remote host is a version prior to 4.1.10. It is, therefore, affected 
by an arbitrary code execution vulnerability. An unauthenticated, remote attacker can exploit this, by convincing a user
to download and open a specially crafted document which contains hyperlinks to  local executables which are executed
unconditionally or on a click by the victim.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version");
  # https://www.openoffice.org/security/cves/CVE-2021-30245.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45f74607");
  # https://cwiki.apache.org/confluence/display/OOOUSERS/AOO+4.1.10+Release+Notes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?229baff5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache OpenOffice version 4.1.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30245");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:openoffice");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openoffice_installed.nasl");
  script_require_keys("installed_sw/OpenOffice");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::openoffice::get_app_info();
var constraints = [{'fixed_version': '9807', 'fixed_display': '4.1.10 (Build 9807)'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
