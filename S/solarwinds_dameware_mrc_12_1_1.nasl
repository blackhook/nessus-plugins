#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140041);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2020-5734");
  script_xref(name:"IAVA", value:"2020-A-0392-S");

  script_name(english:"SolarWinds DameWare Mini Remote Control < 12.1.1 Denial of Service");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a remote management application that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of SolarWinds DameWare Mini Remote Control prior to 12.1.1. It is, therefore,
affected by a denial of service vulnerability. A classic buffer overflow allows a remote, unauthenticated attacker to
cause a denial of service by sending a large 'SigPubkeyLen' during ECDH key exchange.");
  # https://documentation.solarwinds.com/en/success_center/dameware/Content/release_notes/Dameware_12-1-1_release_notes.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76b78a79");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds DameWare Mini Remote Control v12.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5734");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:solarwinds:dameware_mini_remote_control");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_dameware_mini_remote_control_installed.nbin");
  script_require_keys("installed_sw/SolarWinds DameWare Mini Remote Control");

  exit(0);
}

include('vcf.inc');

app = vcf::get_app_info(app:'SolarWinds DameWare Mini Remote Control', win_local:TRUE);

constraints = [{'fixed_version' : '12.1.1'}];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);

