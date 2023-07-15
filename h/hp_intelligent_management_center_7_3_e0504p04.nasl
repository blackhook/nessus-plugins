#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100869);
  script_version("1.12");
  script_cvs_date("Date: 2018/11/15 20:50:27");

  script_cve_id(
    "CVE-2016-7053",
    "CVE-2016-7054",
    "CVE-2016-7055",
    "CVE-2017-5815",
    "CVE-2017-5816",
    "CVE-2017-5817",
    "CVE-2017-5818",
    "CVE-2017-5819",
    "CVE-2017-5820",
    "CVE-2017-5821",
    "CVE-2017-5822",
    "CVE-2017-5823",
    "CVE-2017-8948",
    "CVE-2017-8956"
  );
  script_bugtraq_id(
    94238,
    94242,
    94244,
    98469,
    98493
  );
  script_xref(name:"HP", value:"emr_na-hpesbhf03743en_us");
  script_xref(name:"IAVA", value:"2017-A-0193");
  script_xref(name:"HP", value:"emr_na-hpesbhf03744en_us");
  script_xref(name:"HP", value:"emr_na-hpesbhf03745en_us");
  script_xref(name:"HP", value:"emr_na-hpesbhf03746en_us");
  script_xref(name:"HP", value:"HPESBHF03743");
  script_xref(name:"HP", value:"HPESBHF03744");
  script_xref(name:"HP", value:"HPESBHF03745");
  script_xref(name:"HP", value:"HPESBHF03746");

  script_name(english:"H3C / HPE Intelligent Management Center PLAT < 7.3 E0504P04 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of HPE Intelligent Management Center.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HPE Intelligent Management Center (iMC) PLAT installed
on the Windows host is prior to 7.3 E0504P04. It is, therefore,
affected by multiple vulnerabilities :

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2017-5815)

  - A command injection vulnerability exists in the dbman
    service due to improper validation of user-supplied
    input before it is passed to a system call. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted opcode 10008 request, to inject and
    execute arbitrary OS commands with SYSTEM privileges.
    (CVE-2017-5816)

  - Multiple command injection vulnerabilities exist in the
    dbman service due to improper validation of
    user-supplied input before it is passed to a system
    call. An unauthenticated, remote attacker can exploit
    these, via a specially crafted opcode 10007 request, to
    inject and execute arbitrary OS commands with SYSTEM
    privileges. (CVE-2017-5817, CVE-2017-5819)

  - A flaw exists in the dbman service when handling opcode
    10007 requests due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, via a specially crafted request, to
    delete arbitrary files with SYSTEM privileges.
    (CVE-2017-5818)

  - A flaw exists in the dbman service when handling opcode
    10004 requests due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, via a specially crafted request, to
    execute arbitrary code. (CVE-2017-5820)

  - A flaw exists in the dbman service when handling opcode
    10006 and 10010 requests due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, via a specially request, to execute
    arbitrary code. (CVE-2017-5821)

  - A flaw exists in the dbman service when handling opcode
    10010 requests due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, via a specially crafted request, to
    execute arbitrary code. (CVE-2017-5822)

  - A flaw exists in the dbman service when handling opcode
    10013 requests due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, via a specially crafted request, to
    execute arbitrary code. (CVE-2017-5823)

  - A NULL pointer deference flaw exists, specifically in
    the asn1_item_embed_d2i() function within file
    crypto/asn1/tasn_dec.c, when handling the ASN.1 CHOICE
    type, which results in a NULL value being passed to the
    structure callback if an attempt is made to free certain
    invalid encodings. An unauthenticated, remote attacker
    can exploit this to cause a denial of service condition.
    (CVE-2016-7053)

  - A heap overflow condition exists in the
    chacha20_poly1305_cipher() function within file
    crypto/evp/e_chacha20_poly1305.c when handling TLS
    connections using *-CHACHA20-POLY1305 cipher suites. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2016-7054)

  - A carry propagation error exists in the
    Broadwell-specific Montgomery multiplication procedure
    when handling input lengths divisible by but longer than
    256 bits. This can result in transient authentication
    and key negotiation failures or reproducible erroneous
    outcomes of public-key operations with specially crafted
    input. A man-in-the-middle attacker can possibly exploit
    this issue to compromise ECDH key negotiations that
    utilize Brainpool P-512 curves. (CVE-2016-7055)

  - An unspecified remote code execution vulnerability
    exists that allows an unauthenticated, remote attacker
    to execute arbitrary code. (CVE-2017-8948)

  - A stack-based buffer overflow condition exists due to
    improper validation of input when copying data. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2017-8956)

Note that Intelligent Management Center (iMC) is an HPE product;
however, it is branded as H3C.");
  # https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03743en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7b8f2f9");
  # https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03744en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d91a76d");
  # https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03745en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f3805b9");
  # https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03746en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f11837c8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to H3C / HPE iMC version 7.3 E0504P04 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HPE iMC dbman RestoreDBase Unauthenticated RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:intelligent_management_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("hp_intelligent_management_center_installed.nasl");
  script_require_keys("installed_sw/HP Intelligent Management Center Application");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'HP Intelligent Management Center Application';

# Pull the installation information from the KB.
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

path = install['path'];
version = install['version'];
# keep track of patch version for 7.3
patchver = FALSE;

build = get_kb_item('SMB/HP_iMC/build');

fixed_display = '7.3 E0504;P04';

fix = NULL;
patchfix = NULL;

if (version =~ "^[0-6](\.[0-9]+)*$" || # e.g. 5, 6.999
    version =~ "^7\.0([0-9]|\.[0-9]+)*$" || # e.g. 7.01, 7.0.2
    version =~ "^7(\.[0-2])?$" # e.g. 7, 7.1, 7.2
)
{
  fix = "7.3";
}

# check patch version if 7.3
else if (version == "7.3")
{
  # Versions < 7.3 E0504P04, remove letters in patch version (if patched)
  patchparts = split(build, sep:";");
  if (max_index(patchparts) > 1) patchver = ereg_replace(string:build, pattern:"[A-Z;]", replace:"");
  # if it doesn't have a semicolon we got a weird version somehow.
  if (!patchver) audit(AUDIT_UNKNOWN_APP_VER, 'HP Intelligent Management Center');

  patchfix = "050404";
}

# if pre 7.3 or 7.3 with patchver before 050404
if ((!isnull(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) < 0) ||
    (!isnull(patchfix) && ver_compare(ver:patchver, fix:patchfix, strict:FALSE) < 0))
{
  port = get_kb_item("SMB/transport");
  if (isnull(port))
    port = 445;

  items = make_array("Installed version", version + ' ' + build,
                     "Fixed version", fixed_display,
                     "Path", path
                    );

  order = make_list("Path", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);

}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
