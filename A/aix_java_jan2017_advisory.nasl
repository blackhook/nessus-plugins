#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103190);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id(
    "CVE-2016-2183",
    "CVE-2016-5546",
    "CVE-2016-5547",
    "CVE-2016-5548",
    "CVE-2016-5549",
    "CVE-2016-5552",
    "CVE-2017-3231",
    "CVE-2017-3241",
    "CVE-2017-3252",
    "CVE-2017-3253",
    "CVE-2017-3259",
    "CVE-2017-3261",
    "CVE-2017-3272",
    "CVE-2017-3289"
  );
  script_bugtraq_id(
    92630,
    95488,
    95498,
    95506,
    95509,
    95512,
    95521,
    95525,
    95530,
    95533,
    95559,
    95563,
    95566,
    95570
  );

  script_name(english:"AIX Java Advisory : java_jan2017_advisory.asc (January 2017 CPU) (SWEET32)");
  script_summary(english:"Checks the version of the Java package.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Java SDK installed on the remote AIX host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Java SDK installed on the remote AIX host is affected
by multiple vulnerabilities in the following subcomponents :

  - A vulnerability exists in the Libraries subcomponent,
    known as SWEET32, in the 3DES and Blowfish algorithms
    due to the use of weak 64-bit block ciphers by default.
    A man-in-the-middle attacker who has sufficient
    resources can exploit this vulnerability, via a
    'birthday' attack, to detect a collision that leaks the
    XOR between the fixed secret and a known plaintext,
    allowing the disclosure of the secret text, such as
    secure HTTPS cookies, and possibly resulting in the
    hijacking of an authenticated session. (CVE-2016-2183)

  - An unspecified flaw exists in the Libraries subcomponent
    that allows an unauthenticated, remote attacker to
    impact integrity. (CVE-2016-5546)

  - An unspecified flaw exists in the Libraries subcomponent
    that allows an unauthenticated, remote attacker to cause
    a denial of service condition. (CVE-2016-5547)

  - Multiple unspecified flaws exist in the Libraries
    subcomponent that allow an unauthenticated, remote
    attacker to disclose sensitive information.
    (CVE-2016-5548, CVE-2016-5549)

  - An unspecified flaw exists in the Networking
    subcomponent that allows an unauthenticated, remote
    attacker to impact integrity. (CVE-2016-5552)

  - Multiple unspecified flaws exist in the Networking
    subcomponent that allow an unauthenticated, remote
    attacker to disclose sensitive information.
    (CVE-2017-3231, CVE-2017-3261)

  - An unspecified flaw exists in the RMI subcomponent that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2017-3241)

  - An unspecified flaw exists in the JAAS subcomponent that
    allows an unauthenticated, remote attacker to impact
    integrity. (CVE-2017-3252)

  - An unspecified flaw exists in the 2D subcomponent that
    allows an unauthenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3253)

  - An unspecified flaw exists in the Deployment
    subcomponent that allows an unauthenticated, remote
    attacker to disclose sensitive information.
    (CVE-2017-3259)

  - An unspecified flaw exists in the AWT subcomponent that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2017-3260)

  - An unspecified flaw exists in the Libraries subcomponent
    that allows an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2017-3272)

  - An unspecified flaw exists in the Hotspot subcomponent
    that allows an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2017-3289)

Note that CVE-2017-3241 can only be exploited by supplying data to
APIs in the specified component without using untrusted Java Web Start
applications or untrusted Java applets, such as through a web service.
Note that CVE-2016-2183, CVE-2016-5546, CVE-2016-5547, CVE-2016-5552,
CVE-2017-3252, and CVE-2017-3253 can be exploited through sandboxed
Java Web Start applications and sandboxed Java applets. They can also
be exploited by supplying data to APIs in the specified component
without using sandboxed Java Web Start applications or sandboxed Java
applets, such as through a web service.");
  # https://aix.software.ibm.com/aix/efixes/security/java_jan2017_advisory.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?894babd4");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=6.0.0.0&platform=AIX+32-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce533d8f");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=6.0.0.0&platform=AIX+64-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17d05c61");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.0.0.0&platform=AIX+32-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4595696");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.0.0.0&platform=AIX+64-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9abd5252");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.1.0.0&platform=AIX+32-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ee03dc1");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.1.0.0&platform=AIX+64-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f7a066c");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=8.0.0.0&platform=AIX+32-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52d4ddf3");
  # https://www-945.ibm.com/support/fixcentral/swg/selectFixes?
  # parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=8.0.0.0&platform=AIX+64-bit,+pSeries&function=all
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?343fa903");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89a8e429");
  script_set_attribute(attribute:"solution", value:
"Fixes are available by version and can be downloaded from the IBM AIX
website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/13");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version", "Host/AIX/oslevelsp");

  exit(0);
}

include("aix.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
oslevel = get_kb_item_or_exit("Host/AIX/version");
if ( oslevel != "AIX-5.3" && oslevel != "AIX-6.1" && oslevel != "AIX-7.1" && oslevel != "AIX-7.2" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 5.3 / 6.1 / 7.1 / 7.2", oslevel);
}

oslevelcomplete = chomp(get_kb_item("Host/AIX/oslevelsp"));
if (empty_or_null(oslevelcomplete)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

flag = 0;

#Java6 6.0.0.641
if (aix_check_package(release:"5.3", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.640", fixpackagever:"6.0.0.641") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.640", fixpackagever:"6.0.0.641") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.640", fixpackagever:"6.0.0.641") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.640", fixpackagever:"6.0.0.641") > 0) flag++;
if (aix_check_package(release:"5.3", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.640", fixpackagever:"6.0.0.641") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.640", fixpackagever:"6.0.0.641") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.640", fixpackagever:"6.0.0.641") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.640", fixpackagever:"6.0.0.641") > 0) flag++;

#Java7 7.0.0.601
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.600", fixpackagever:"7.0.0.601") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.600", fixpackagever:"7.0.0.601") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.600", fixpackagever:"7.0.0.601") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.600", fixpackagever:"7.0.0.601") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.600", fixpackagever:"7.0.0.601") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.600", fixpackagever:"7.0.0.601") > 0) flag++;

#Java7.1 7.1.0.401
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.400", fixpackagever:"7.1.0.401") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.400", fixpackagever:"7.1.0.401") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.400", fixpackagever:"7.1.0.401") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.400", fixpackagever:"7.1.0.401") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.400", fixpackagever:"7.1.0.401") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.400", fixpackagever:"7.1.0.401") > 0) flag++;

#Java8.0 8.0.0.401
if (aix_check_package(release:"6.1", package:"Java8.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.400", fixpackagever:"8.0.0.401") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java8.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.400", fixpackagever:"8.0.0.401") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java8.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.400", fixpackagever:"8.0.0.401") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java8_64.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.400", fixpackagever:"8.0.0.401") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java8_64.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.400", fixpackagever:"8.0.0.401") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java8_64.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.400", fixpackagever:"8.0.0.401") > 0) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : aix_report_get()
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Java6 / Java7 / Java8");
}
