#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(131942);
  script_version("1.1");
  script_cvs_date("Date: 2019/12/11");

  script_name(english:"Foxit Studio Photo < 3.6.6.916 Out-of-Bounds Read Vulnerability");
  script_summary(english:"Checks the version of Foxit Studio Photo");

  script_set_attribute(attribute:"synopsis", value:
"A photo editor application installed on the remote Windows host is affected by an Out-of-Bounds Read vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Foxit Studio Photo application installed on the remote Windows host is
affected by an out-of-bounds read error in the preview creation of EPS files due to improper validation of user-supplied              
data. An unauthenticated, remote attacker can exploit this, to disclose potentially sensitive information or cause the
application to stop responding.");
  # https://www.foxitsoftware.com/support/security-bulletins.php
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f244c3e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Studio Photo 3.6.6.916 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_studio_photo");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_studio_photo_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Foxit Studio Photo");

  exit(0);
}

include('vcf.inc');

app = 'Foxit Studio Photo';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'fixed_version' : '3.6.6.916' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
