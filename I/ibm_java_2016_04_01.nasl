#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160367);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/25");

  script_cve_id("CVE-2016-0264", "CVE-2016-0363", "CVE-2016-0376");

  script_name(english:"IBM Java 6.0 < 6.0.16.25 / 6.1 < 6.1.8.25 / 7.0 < 7.0.9.40 / 7.1 < 7.1.3.40 / 8.0 < 8.0.3.0 Multiple Vulnerabilities (Apr 1, 2016)");

  script_set_attribute(attribute:"synopsis", value:
"IBM Java is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Java installed on the remote host is prior to 6.0 < 6.0.16.25 / 6.1 < 6.1.8.25 / 7.0 < 7.0.9.40 / 7.1
< 7.1.3.40 / 8.0 < 8.0.3.0. It is, therefore, affected by multiple vulnerabilities as referenced in the IBM Security
Update April 2016 advisory.

  - Buffer overflow in the Java Virtual Machine (JVM) in IBM SDK, Java Technology Edition 6 before SR16 FP25
    (6.0.16.25), 6 R1 before SR8 FP25 (6.1.8.25), 7 before SR9 FP40 (7.0.9.40), 7 R1 before SR3 FP40
    (7.1.3.40), and 8 before SR3 (8.0.3.0) allows remote attackers to execute arbitrary code via unspecified
    vectors. (CVE-2016-0264)

  - The com.ibm.CORBA.iiop.ClientDelegate class in IBM SDK, Java Technology Edition 6 before SR16 FP25
    (6.0.16.25), 6 R1 before SR8 FP25 (6.1.8.25), 7 before SR9 FP40 (7.0.9.40), 7 R1 before SR3 FP40
    (7.1.3.40), and 8 before SR3 (8.0.3.0) uses the invoke method of the java.lang.reflect.Method class in an
    AccessController doPrivileged block, which allows remote attackers to call setSecurityManager and bypass a
    sandbox protection mechanism via vectors related to a Proxy object instance implementing the
    java.lang.reflect.InvocationHandler interface. NOTE: this vulnerability exists because of an incomplete
    fix for CVE-2013-3009. (CVE-2016-0363)

  - The com.ibm.rmi.io.SunSerializableFactory class in IBM SDK, Java Technology Edition 6 before SR16 FP25
    (6.0.16.25), 6 R1 before SR8 FP25 (6.1.8.25), 7 before SR9 FP40 (7.0.9.40), 7 R1 before SR3 FP40
    (7.1.3.40), and 8 before SR3 (8.0.3.0) does not properly deserialize classes in an AccessController
    doPrivileged block, which allows remote attackers to bypass a sandbox protection mechanism and execute
    arbitrary code as demonstrated by the readValue method of the
    com.ibm.rmi.io.ValueHandlerPool.ValueHandlerSingleton class, which implements the
    javax.rmi.CORBA.ValueHandler interface. NOTE: this vulnerability exists because of an incomplete fix for
    CVE-2013-5456. (CVE-2016-0376)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV84035");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IX90171");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IX90172");
  # https://www.ibm.com/support/pages/java-sdk-security-vulnerabilities#IBM_Security_Update_April_2016
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7af83b6a");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the IBM Security Update April 2016 advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0363");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:java");
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
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.16.25' },
  { 'min_version' : '6.1.0', 'fixed_version' : '6.1.8.25' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.9.40' },
  { 'min_version' : '7.1.0', 'fixed_version' : '7.1.3.40' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.3.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
