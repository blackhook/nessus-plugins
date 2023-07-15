#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(142882);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/14");

  script_cve_id("CVE-2020-13958");
  script_xref(name:"IAVA", value:"2020-A-0525-S");

  script_name(english:"Apache OpenOffice < 4.1.8 Arbitrary Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache OpenOffice installed on the remote host is a version prior to 4.1.8. It is, therefore, affected 
by an arbitrary code execution vulnerability in its scripting events component. An unauthenticated, remote attacker can 
exploit this, by convincing a user to download and open a specially crafted document which contains hyperlinks to 
local executables which are executed unconditionally or on a click by the victim.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version");
  # https://www.openoffice.org/security/cves/CVE-2020-13958.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67dcd958");
  # https://cwiki.apache.org/confluence/display/OOOUSERS/AOO+4.1.8+Release+Notes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f517b77b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache OpenOffice version 4.1.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13958");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:openoffice");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openoffice_installed.nasl");
  script_require_keys("installed_sw/OpenOffice");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::openoffice::get_app_info();
constraints = [{'fixed_version': '9803', 'fixed_display': '4.1.8 (Build 9803)'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
