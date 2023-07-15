#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117427);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-1149", "CVE-2018-1150");
  script_xref(name:"TRA", value:"TRA-2018-25");

  script_name(english:"NUUO NVRMini2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of NUUO NVRMini2.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of NUUO NVRMini2 installed on the remote host is affected
by multiple vulnerabilities:

  - NUUO NVRMini2 web server utilizes CGI binaries in order to handle
    a variety of commands that require authenticated interaction.
    Implemented session handling mechanism doesn't validate user's
    input properly. Malicious attackers can trigger stack overflow
    in session management routines in order to execute arbitrary
    code. (CVE-2018-1149)

  - NUUO NVRMini2 web server contains back door functionality. Back
    door PHP code (when enabled) allows unauthenticated attacker to
    change a password for any registered user except administrator
    of the system. (CVE-2018-1150)");
  script_set_attribute(attribute:"solution", value:
"All users of NUUO NVRMini2 should upgrade to version 3.9.1
(03.09.0001.0000) or later. Otherwise, contact the vendor for a fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1149");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nuuo:nvrmini_2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nuuo_netgear_www_video_detect.nbin");
  script_require_keys("installed_sw/NUUO NVR");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http.inc");
include("vcf.inc");

app_name = "NUUO NVR";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:80, embedded:TRUE, php:TRUE);

app = vcf::get_app_info(app:app_name, webapp:TRUE, port:port);
vcf::check_granularity(app_info:app, sig_segments:4);

constraints = [
  {
    "fixed_version":"03.09.0001.0000",
    "fixed_display":"3.9.1 (03.09.0001.0000)"
  }];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE);

