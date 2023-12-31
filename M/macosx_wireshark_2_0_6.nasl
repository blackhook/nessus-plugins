#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93517);
  script_version("1.7");
  script_cvs_date("Date: 2018/07/16 12:48:31");

  script_cve_id(
    "CVE-2016-7175",
    "CVE-2016-7176",
    "CVE-2016-7177",
    "CVE-2016-7178",
    "CVE-2016-7179",
    "CVE-2016-7180"
  );
  script_bugtraq_id(92889);

  script_name(english:"Wireshark 2.0.x < 2.0.6 Multiple DoS (Mac OS X)");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has an application installed that is affected
by multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Mac OS X host is
2.0.x prior to 2.0.6. It is, therefore, affected by multiple denial of
service vulnerabilities :

  - A flaw exists in the QNX6 QNET dissector in the
    dissect_qnet6_lr() function in packet-qnet6.c due to
    improper handling of MAC address data. An
    unauthenticated, remote attacker can exploit this, via a
    crafted packet, to crash the program, resulting in a
    denial of service. (CVE-2016-7175)

  - Multiple flaws exist in the H.225 dissector in
    packet-h225.c due to improper handling of strings in
    malformed packets. An unauthenticated, remote attacker
    can exploit this, via a crafted packet, to crash the
    program, resulting in a denial of service.
    (CVE-2016-7176)

  - An out-of-bounds read error exists in the Catapult
    DCT2000 dissector in the attach_fp_info() function in
    packet-catapult-dct2000.c due to a failure to restrict
    the number of channels. An unauthenticated, remote
    attacker can exploit this, via a crafted packet, to
    crash the program, resulting in a denial of service.
    (CVE-2016-7177)

  - A NULL pointer dereference flaw exists in the UMTS FP
    dissector in packet-umts_fp.c due to a failure to ensure
    that memory is allocated for certain data structures. An
    unauthenticated, remote attacker can exploit this, via a
    crafted packet, to crash the program, resulting in a
    denial of service. (CVE-2016-7178)

  - A stack-based buffer overflow condition exists in the
    Catapult DCT2000 dissector in the parse_outhdr_string()
    function in packet-catapult-dct2000.c due to improper
    validation of specially crafted packets. An
    unauthenticated, remote attacker can exploit this, via a
    crafted packet, to crash the program, resulting in a
    denial of service. (CVE-2016-7179)

  - A flaw exists in the IPMI Trace dissector in the
    dissect_ipmi_trace() function in packet-ipmi-trace.c due
    to a failure to properly consider whether a string is
    constant. An unauthenticated, remote attacker can
    exploit this, via a crafted packet, to crash the
    program, resulting in a denial of service.
    (CVE-2016-7180)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-50.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-51.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-52.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-53.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-54.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-55.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.0.6.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");

  script_dependencies("macosx_wireshark_installed.nbin");
  script_require_keys("installed_sw/Wireshark");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit("Host/MacOSX/Version");

app_name = "Wireshark";
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];
fix = '2.0.6';

# Affected :
#  2.0.x < 2.0.6
if (version =~ '^2\\.0\\.' && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
