#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160350);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/25");

  script_cve_id(
    "CVE-2016-0705",
    "CVE-2017-3732",
    "CVE-2017-3736",
    "CVE-2018-1517",
    "CVE-2018-1656",
    "CVE-2018-12539"
  );
  script_xref(name:"IAVA", value:"2016-A-0056-S");
  script_xref(name:"IAVB", value:"2016-B-0083-S");
  script_xref(name:"IAVA", value:"2017-A-0228-S");
  script_xref(name:"IAVA", value:"2017-A-0032-S");
  script_xref(name:"IAVA", value:"2017-A-0224-S");
  script_xref(name:"IAVA", value:"2018-A-0117-S");
  script_xref(name:"IAVA", value:"2018-A-0033-S");
  script_xref(name:"IAVA", value:"2017-A-0327-S");
  script_xref(name:"IAVA", value:"2018-A-0118-S");
  script_xref(name:"IAVA", value:"2019-A-0130");

  script_name(english:"IBM Java 6.0 < 6.0.16.70 / 6.1 < 6.1.8.70 / 7.0 < 7.0.10.30 / 7.1 < 7.1.4.30 / 8.0 < 8.0.5.20 Multiple Vulnerabilities (Aug 1, 2018)");

  script_set_attribute(attribute:"synopsis", value:
"IBM Java is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Java installed on the remote host is prior to 6.0 < 6.0.16.70 / 6.1 < 6.1.8.70 / 7.0 < 7.0.10.30 /
7.1 < 7.1.4.30 / 8.0 < 8.0.5.20. It is, therefore, affected by multiple vulnerabilities as referenced in the IBM
Security Update August 2018 advisory.

  - Double free vulnerability in the dsa_priv_decode function in crypto/dsa/dsa_ameth.c in OpenSSL 1.0.1
    before 1.0.1s and 1.0.2 before 1.0.2g allows remote attackers to cause a denial of service (memory
    corruption) or possibly have unspecified other impact via a malformed DSA private key. (CVE-2016-0705)

  - There is a carry propagating bug in the x86_64 Montgomery squaring procedure in OpenSSL 1.0.2 before
    1.0.2k and 1.1.0 before 1.1.0d. No EC algorithms are affected. Analysis suggests that attacks against RSA
    and DSA as a result of this defect would be very difficult to perform and are not believed likely. Attacks
    against DH are considered just feasible (although very difficult) because most of the work necessary to
    deduce information about a private key may be performed offline. The amount of resources required for such
    an attack would be very significant and likely only accessible to a limited number of attackers. An
    attacker would additionally need online access to an unpatched system using the target private key in a
    scenario with persistent DH parameters and a private key that is shared between multiple clients. For
    example this can occur by default in OpenSSL DHE based SSL/TLS ciphersuites. Note: This issue is very
    similar to CVE-2015-3193 but must be treated as a separate problem. (CVE-2017-3732)

  - There is a carry propagating bug in the x86_64 Montgomery squaring procedure in OpenSSL before 1.0.2m and
    1.1.0 before 1.1.0g. No EC algorithms are affected. Analysis suggests that attacks against RSA and DSA as
    a result of this defect would be very difficult to perform and are not believed likely. Attacks against DH
    are considered just feasible (although very difficult) because most of the work necessary to deduce
    information about a private key may be performed offline. The amount of resources required for such an
    attack would be very significant and likely only accessible to a limited number of attackers. An attacker
    would additionally need online access to an unpatched system using the target private key in a scenario
    with persistent DH parameters and a private key that is shared between multiple clients. This only affects
    processors that support the BMI1, BMI2 and ADX extensions like Intel Broadwell (5th generation) and later
    or AMD Ryzen. (CVE-2017-3736)

  - A flaw in the java.math component in IBM SDK, Java Technology Edition 6.0, 7.0, and 8.0 may allow an
    attacker to inflict a denial-of-service attack with specially crafted String data. IBM X-Force ID: 141681.
    (CVE-2018-1517)

  - The IBM Java Runtime Environment's Diagnostic Tooling Framework for Java (DTFJ) (IBM SDK, Java Technology
    Edition 6.0 , 7.0, and 8.0) does not protect against path traversal attacks when extracting compressed
    dump files. IBM X-Force ID: 144882. (CVE-2018-1656)

  - In Eclipse OpenJ9 version 0.8, users other than the process owner may be able to use Java Attach API to
    connect to an Eclipse OpenJ9 or IBM JVM on the same machine and use Attach API operations, which includes
    the ability to execute untrusted native code. Attach API is enabled by default on Windows, Linux and AIX
    JVMs and can be disabled using the command line option -Dcom.ibm.tools.attach.enable=no. (CVE-2018-12539)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ07855");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ08248");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ08250");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ08278");
  # https://www.ibm.com/support/knowledgecenter/en/SSYKE2_8.0.0/com.ibm.java.security.component.80.doc/security-component/jceplusdocs/jceplus.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a20a1bce");
  # https://www.ibm.com/support/pages/java-sdk-security-vulnerabilities#IBM_Security_Update_August_2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40e319ff");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the IBM Security Update August 2018 advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0705");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:java");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_java_nix_installed.nbin", "ibm_java_win_installed.nbin");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['IBM Java'];
var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.16.70' },
  { 'min_version' : '6.1.0', 'fixed_version' : '6.1.8.70' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.10.30' },
  { 'min_version' : '7.1.0', 'fixed_version' : '7.1.4.30' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.5.20' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
