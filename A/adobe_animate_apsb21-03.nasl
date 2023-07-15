##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144946);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2021-21008");
  script_xref(name:"IAVA", value:"2021-A-0020-S");

  script_name(english:"Adobe Animate < 21.0.2 Arbitrary Code Execution (APSB21-03)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Animate installed on the remote Windows host is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Animate installed on the remote Windows host is version less than 21.0.2. It is, therefore,
affected by a vulnerability which allows arbitrary code execution in the context of the current user. This is due to an
uncontrolled search path element.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://helpx.adobe.com/security/products/animate/apsb21-03.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c024e6b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Animate version 21.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21008");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:animate");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_animate_installed.nbin");
  script_require_keys("installed_sw/Adobe Animate", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe Animate', win_local:TRUE);

constraints = [
  { 'fixed_version' : '21.0.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
