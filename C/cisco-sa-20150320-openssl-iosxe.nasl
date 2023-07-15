#TRUSTED a4c53503c388e2f66ee2ed51343b9713c6f0cd34004b8452855a574e3b1f202bb9fa7ff9c2cef512e1f92c563d8a54760552a0e9dd87f4899c116e4d2b6a7c2be07823878ebc9d5295cedeeff1679763f3facb87d83d0f97458ec717566a5640856f93ab0532bbcc619e6330d63de02f45c55cb3ac2e07883be3de297d39e4695fa62445ef63b00dd9387102377eeec2013b929664919bdc378f16b33ce6765b399b843cef51c40f28a2409a11deec2d032ee559d9a702d9ee604cbc8979d6a25065fa4c2cd6975ad70e439352f32e21285d06738a03b771221b731cc740986892cc1c65422009fdf54347bac58f85a6cd9e33a817dc7b07d8d8cc57ec48c1385483e93fc03383cf4613cd6318314766b52992425677cf5c0c73cbf83231c6df056bd5b9ee2a36992f01af89f2d5a16a0ad19efdba7101c406bda57ff7ac9c9519f19329edab6cc3d879d08c1c9297bfa1853d7763ae3d76c53ba8925de39ebe2048fe255d898f51cb31e27f16438bedb13120636879e64a32e0319db980b383ba1607539aa91849cb4d84104f9f16add571513ef6f866f77c534fab2411a19d20fbbd858d79dcc19e1c122c3a3c27828c2ac2276513a79981475bd32e2b7b1af8cda347c7b081589bfa50621e271da231517491bc5cb52e0df8f2468dba161079a31b9c830af162264f69f447f39b77af4a287bcff868e9fb1e1e98f96671ab
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90526);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/19");

  script_cve_id(
    "CVE-2015-0209",
    "CVE-2015-0286",
    "CVE-2015-0287",
    "CVE-2015-0288",
    "CVE-2015-0289",
    "CVE-2015-0292",
    "CVE-2015-0293"
  );
  script_bugtraq_id(
    73225,
    73227,
    73228,
    73231,
    73232,
    73237,
    73239
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCut46130");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut46126");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150320-openssl");

  script_name(english:"Cisco IOS XE Multiple OpenSSL Vulnerabilities (CSCut46130 / CSCut46126)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is missing a vendor-supplied security
patch and has an IOS service configured to use TLS or SSL. It is,
therefore, affected by the following vulnerabilities in the bundled
OpenSSL library :

  - A use-after-free condition exists in the
    d2i_ECPrivateKey() function due to improper processing
    of malformed EC private key files during import. A
    remote attacker can exploit this to dereference or free
    already freed memory, resulting in a denial of service
    or other unspecified impact. (CVE-2015-0209)

  - An invalid read error exists in the ASN1_TYPE_cmp()
    function due to improperly performed boolean-type
    comparisons. A remote attacker can exploit this, via a
    crafted X.509 certificate to an endpoint that uses the
    certificate-verification feature, to cause an invalid
    read operation, resulting in a denial of service.
    (CVE-2015-0286)

  - A flaw exists in the ASN1_item_ex_d2i() function due to
    a failure to reinitialize 'CHOICE' and 'ADB' data
    structures when reusing a structure in ASN.1 parsing.
    This allows a remote attacker to cause an invalid write
    operation and memory corruption, resulting in a denial
    of service. (CVE-2015-0287)

  - A NULL pointer dereference flaw exists in the
    X509_to_X509_REQ() function due to improper processing
    of certificate keys. This allows a remote attacker, via
    a crafted X.509 certificate, to cause a denial of
    service. (CVE-2015-0288)

  - A NULL pointer dereference flaw exists in the PKCS#7
    parsing code due to incorrect handling of missing outer
    ContentInfo. This allows a remote attacker, using an
    application that processes arbitrary PKCS#7 data and
    providing malformed data with ASN.1 encoding, to cause
    a denial of service. (CVE-2015-0289)

  - An integer underflow condition exists in the
    EVP_DecodeUpdate() function due to improper validation
    of base64 encoded input when decoding. This allows a
    remote attacker, using maliciously crafted base64 data,
    to cause a segmentation fault or memory corruption,
    resulting in a denial of service or possibly the
    execution of arbitrary code. (CVE-2015-0292)

  - A flaw exists in servers that both support SSLv2 and
    enable export cipher suites due to improper
    implementation of SSLv2. A remote attacker can exploit
    this, via a crafted CLIENT-MASTER-KEY message, to cause
    a denial of service. (CVE-2015-0293)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150320-openssl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2beef118");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCut46130");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150319.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCut46130.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version  = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
##
# Examines the output of show running config all for evidence
# the WebUI is running and using SSL
#
# @remark 'override' in the return value signals that the scan
#         was not provided sufficient credentials to check for
#         the related configurations. 'flag' signals whether or
#         not the configuration examined shows the webui with
#         SSL is enabled
#
# @return always an array like:
# {
#   'override' : (TRUE|FALSE),
#   'flag'     : (TRUE|FALSE)
# }
##
function iosxe_webui_ssl()
{
  local_var res, buf;
  res = make_array(
    'override',  TRUE,
    'flag',      TRUE
  );

  # Signal we need local checks
  if (!get_kb_item("Host/local_checks_enabled"))
    return res;

  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config_all",
    "show running-config all"
  );

  # Privilege escalation required
  if (cisco_needs_enable(buf))
    return res;

  res['flag'] = FALSE;

  # Check to make sure no errors in command output
  if(!check_cisco_result(buf))
    return res;

  # All good check for various SSL services
  res['override'] = FALSE;

   # Web UI HTTPS
  if (preg(string:buf, pattern:"^ip http secure-server", multiline:TRUE))
    res['flag'] = TRUE;

  return res;
}

##
# Main check logic
##

flag = 0;
if (version == "3.11.0S") flag++;
if (version == "3.12.0S") flag++;
if (version == "3.13.0S") flag++;
if (version == "3.14.0S") flag++;
if (version == "3.15.0S") flag++;

if (!flag)
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XE", version);

# Configuration check
sslcheck = iosxe_webui_ssl();

if (!sslcheck['flag'] && !sslcheck['override'])
  audit(AUDIT_HOST_NOT, "affected because it appears the WebUI is not enabled or not using SSL/TLS");

# Override is shown regardless of verbosity
report = "";
if (report_verbosity > 0)
{
  order  = make_list('Cisco bug ID', 'Installed release');
  report = make_array(
    order[0], 'CSCut46130 / CSCut46126',
    order[1], version
  );
  report = report_items_str(report_items:report, ordered_fields:order);
}

security_hole(port:0, extra:report+cisco_caveat(sslcheck['override']));
