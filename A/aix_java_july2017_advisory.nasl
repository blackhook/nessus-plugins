#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103191);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id(
    "CVE-2017-1376",
    "CVE-2017-1541",
    "CVE-2017-10053",
    "CVE-2017-10067",
    "CVE-2017-10078",
    "CVE-2017-10087",
    "CVE-2017-10089",
    "CVE-2017-10090",
    "CVE-2017-10096",
    "CVE-2017-10101",
    "CVE-2017-10102",
    "CVE-2017-10105",
    "CVE-2017-10107",
    "CVE-2017-10108",
    "CVE-2017-10109",
    "CVE-2017-10110",
    "CVE-2017-10115",
    "CVE-2017-10116",
    "CVE-2017-10125",
    "CVE-2017-10243"
  );
  script_bugtraq_id(
    99643,
    99659,
    99670,
    99674,
    99703,
    99706,
    99712,
    99719,
    99734,
    99752,
    99756,
    99774,
    99809,
    99827,
    99842,
    99846,
    99847,
    99851,
    100460
  );

  script_name(english:"AIX Java Advisory : java_july2017_advisory.asc (July 2017 CPU)");
  script_summary(english:"Checks the version of the Java package.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Java SDK installed on the remote AIX host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Java SDK installed on the remote AIX host is affected
by multiple vulnerabilities in the following subcomponents :

  - A flaw exists in the J9 VM class verifier component that
    allows an unauthenticated, remote attacker to cause an
    escalation of privileges. (CVE-2017-1376)

  - A flaw exists in the installp and updatep packages that
    prevents security updates from being correctly applied.
    (CVE-2017-1541)

  - An unspecified flaw exists in the 2D component that
    allows an unauthenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-10053)

  - Multiple unspecified flaws exist in the Security
    component that allow an unauthenticated, remote attacker
    to execute arbitrary code. (CVE-2017-10067,
    CVE-2017-10116)

  - An unspecified flaw exists in the Scripting component
    that allows an authenticated, remote attacker to impact
    confidentiality and integrity. (CVE-2017-10078)

  - Multiple unspecified flaws exist in the Libraries
    component that allow an unauthenticated, remote attacker
    to execute arbitrary code. (CVE-2017-10087,
    CVE-2017-10090)

  - An unspecified flaw exists in the ImageIO component that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2017-10089)

  - Multiple unspecified flaws exist in the JAXP component
    that allow an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2017-10096, CVE-2017-10101)

  - Multiple unspecified flaws exist in the RMI component
    that allow an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2017-10102, CVE-2017-10107)

  - An unspecified flaw exists in the Deployment component
    that allows an unauthenticated, remote attacker to
    impact integrity. (CVE-2017-10105)

  - Multiple unspecified flaws exist in the Serialization
    component that allow an unauthenticated, remote attacker
    to exhaust available memory, resulting in a denial of
    service condition. (CVE-2017-10108, CVE-2017-10109)

  - An unspecified flaw exists in the AWT component that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2017-10110)

  - Multiple unspecified flaws exist in the JCE component
    that allow an unauthenticated, remote attacker to
    disclose sensitive information. (CVE-2017-10115)

  - An unspecified flaw exists in the Deployment component
    that allows a local attacker to impact confidentiality,
    integrity, and availability. (CVE-2017-10125)

  - An unspecified flaw exists in the JAX-WS component that
    allows an unauthenticated, remote attacker to impact
    confidentiality and availability. (CVE-2017-10243)");

  # https://aix.software.ibm.com/aix/efixes/security/java_july2017_advisory.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f03c72d");
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
  # http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76f5def7");
  script_set_attribute(attribute:"solution", value:
"Fixes are available by version and can be downloaded from the IBM AIX
website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1376");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/13");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

#Java6 6.0.0.650
if (aix_check_package(release:"5.3", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.649", fixpackagever:"6.0.0.650") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.649", fixpackagever:"6.0.0.650") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.649", fixpackagever:"6.0.0.650") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.649", fixpackagever:"6.0.0.650") > 0) flag++;
if (aix_check_package(release:"5.3", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.649", fixpackagever:"6.0.0.650") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.649", fixpackagever:"6.0.0.650") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.649", fixpackagever:"6.0.0.650") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.649", fixpackagever:"6.0.0.650") > 0) flag++;

#Java7 7.0.0.610
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.609", fixpackagever:"7.0.0.610") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.609", fixpackagever:"7.0.0.610") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.609", fixpackagever:"7.0.0.610") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.609", fixpackagever:"7.0.0.610") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.609", fixpackagever:"7.0.0.610") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.609", fixpackagever:"7.0.0.610") > 0) flag++;

#Java7.1 7.1.0.410
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.409", fixpackagever:"7.1.0.410") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.409", fixpackagever:"7.1.0.410") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.409", fixpackagever:"7.1.0.410") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.409", fixpackagever:"7.1.0.410") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.409", fixpackagever:"7.1.0.410") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.409", fixpackagever:"7.1.0.410") > 0) flag++;

#Java8.0 8.0.0.410
if (aix_check_package(release:"6.1", package:"Java8.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.409", fixpackagever:"8.0.0.410") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java8.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.409", fixpackagever:"8.0.0.410") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java8.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.409", fixpackagever:"8.0.0.410") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java8_64.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.409", fixpackagever:"8.0.0.410") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java8_64.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.409", fixpackagever:"8.0.0.410") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java8_64.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.409", fixpackagever:"8.0.0.410") > 0) flag++;

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
