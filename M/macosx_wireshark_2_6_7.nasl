#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129298);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/24");

  script_cve_id("CVE-2019-9208", "CVE-2019-9209", "CVE-2019-9214");
  script_bugtraq_id(107203);

  script_name(english:"Wireshark 2.6.x < 2.6.7 Multiple Vulnerabilities (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS / Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote macOS / Mac OS X host is prior to 2.6.7. It is, therefore, affected by
multiple vulnerabilities as referenced in the wireshark-2.6.7 advisory.

  - The ASN.1 BER and related dissectors could crash. It may
    be possible to make Wireshark crash by injecting a
    malformed packet onto the wire or by convincing someone
    to read a malformed packet trace file. (CVE-2019-9209)

  - The TCAP dissector could crash. It may be possible to
    make Wireshark crash by injecting a malformed packet
    onto the wire or by convincing someone to read a
    malformed packet trace file. (CVE-2019-9208)

  - The RPCAP dissector could crash. It may be possible to
    make Wireshark crash by injecting a malformed packet
    onto the wire or by convincing someone to read a
    malformed packet trace file. (CVE-2019-9214)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.6.7.html");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=15447");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2019-06");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=15464");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2019-07");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=15536");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2019-08");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.6.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9214");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_wireshark_installed.nbin");
  script_require_keys("installed_sw/Wireshark", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Wireshark');

constraints = [
  { 'min_version' : '2.6.0', 'fixed_version' : '2.6.7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
