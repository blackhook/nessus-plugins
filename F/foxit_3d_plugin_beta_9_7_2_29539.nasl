#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139233);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/31");

  script_name(english:"Foxit 3D Plugin Beta < 9.7.2.29539 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a Foxit plugin installed that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Foxit 3D plugin installed on the remote Windows host is prior to 9.7.2.29539. It is, therefore 
affected by an Out-of-Bounds Read/Write or Heap-based Buffer Overflow vulnerability due to improper validation of data
when parsing certain file with incorrect 3D annotation data. An unauthenticated, remote attacker can exploit this to
disclose information or execute remote code.");
  # https://www.foxitsoftware.com/support/security-bulletins.php
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f244c3e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit 3D Plugin Beta 9.7.2.29539 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:foxitsoftware:u3dbrowser_plugin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_u3dbrowser_plugin_win_installed.nbin");
  script_require_keys("installed_sw/Foxit U3DBrowser Plugin");

  exit(0);
}

include('vcf.inc');

app_name = 'Foxit U3DBrowser Plugin';

app_info = vcf::get_app_info(app:app_name, win_local:TRUE);

constraints = [
  { 'fixed_version' : '9.7.2.29539' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
