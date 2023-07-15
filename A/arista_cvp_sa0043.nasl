#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138340);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-9512", "CVE-2019-9514", "CVE-2019-9515");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"Arista Networks CloudVision Portal Multiple Vulnerabilities (SA0043)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks CloudVision Portal running on the remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks CloudVision Portal running on the remote device is affected by the following
vulnerabilities:

  - HTTP/2 implementations are vulnerable to ping floods, potentially leading to a denial of service (DoS).
    An unauthenticated, remote attacker can exploit this, by sending continual pings to an HTTP/2 peer,
    causing the peer to build an internal queue of responses. Depending on how efficiently this data is
    queued, this can consume excess CPU, memory, or both. (CVE-2019-9512)

  - HTTP/2 implementations are vulnerable to a reset flood, potentially leading to a DoS. An unauthenticated, 
    remote attacker can open a number of streams and send an invalid request over each stream that should
    solicit a stream of RST_STREAM frames from the peer. Depending on how the peer queues the RST_STREAM
    frames, this can consume excess memory, CPU, or both. (CVE-2019-9514)

  - HTTP/2 implementations are vulnerable to a settings flood, potentially leading to a DoS. An
    unauthenticated, remote attacker can exploit this by sending a stream of SETTINGS frames to the peer.
    Since the RFC requires that the peer reply with one acknowledgement per SETTINGS frame, an empty SETTINGS
    frame is almost equivalent in behavior to a ping. Depending on how efficiently this data is queued, this
    can consume excess CPU, memory, or both. (CVE-2019-9515)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.  To retrieve patch level information this plugin requires the HTTP credentials of the web console.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/8762-security-advisory-43
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5070013");
  script_set_attribute(attribute:"solution", value:
"Apply the mitigation or upgrade to a fixed version as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9515");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:arista:cloudvision_portal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arista_cloudvision_portal_detect.nbin");
  script_require_keys("installed_sw/Arista CloudVision Portal", "Settings/ParanoidReport");

  exit(0);
}

include('http.inc');
include('vcf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

port = get_http_port(default:443);
app = 'Arista CloudVision Portal';

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  {'fixed_version':'2018.2.6', 'fixed_display':'2019.1.0' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
