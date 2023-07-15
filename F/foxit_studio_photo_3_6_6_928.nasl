#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139924);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/02");

  script_cve_id("CVE-2020-17403", "CVE-2020-17404");

  script_name(english:"Foxit Studio Photo < 3.6.6.928 Out-of-Bounds Write");

  script_set_attribute(attribute:"synopsis", value:
"A photo editor application installed on the remote Windows host is affected by an Out-of-Bounds Write RCE.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Foxit Studio Photo application installed on the remote Windows host is
prior to 3.6.6.928. It is, therefore, affected by an out-of-bounds write error when processing PSD files. A remote, 
unauthenticated attacker could trick a victim into opening a specially crafted file to trigger out-of-bounds write
error and execute arbitrary code on the target system.");
  # https://www.foxitsoftware.com/support/security-bulletins.php
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f244c3e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Studio Photo 3.6.6.928 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17404");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_studio_photo");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_studio_photo_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Foxit Studio Photo");

  exit(0);
}

include('vcf.inc');

app = 'Foxit Studio Photo';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'fixed_version' : '3.6.6.928' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);


