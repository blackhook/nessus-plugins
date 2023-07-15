##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144448);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/21");

  script_cve_id("CVE-2020-17411", "CVE-2020-17412", "CVE-2020-17413");

  script_name(english:"Foxit 3D Plugin Beta 9.x < 9.7.4.29600 / 10.x < 10.1.0.37494 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a Foxit plugin installed that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Foxit 3D plugin installed on the remote Windows host is 9.x prior to 9.7.4.29600, or 10.x prior to
10.1.0.37494. It is, therefore  affected by an Out-of-Bounds Read/Write or Stack-based Buffer Overflow vulnerability
due to improper validation of data when parsing certain U3D objects that contain an incorrect data stream. An
unauthenticated, local attacker can exploit this to disclose information or execute remote code.");
  # https://www.foxitsoftware.com/support/security-bulletins.php
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f244c3e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit 3D Plugin Beta 9.7.4.29600, 10.1.0.37494, or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17412");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/18");

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
  { 'min_version' : '9.0', 'max_version' : '9.7.3.29555', 'fixed_version' : '9.7.4.29600' },
  { 'min_version' : '10.0', 'max_version' : '10.0.1.35811', 'fixed_version' : '10.1.0.37494' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
