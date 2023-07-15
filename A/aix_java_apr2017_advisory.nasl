#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103189);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id(
    "CVE-2016-9840",
    "CVE-2016-9841",
    "CVE-2016-9842",
    "CVE-2016-9843",
    "CVE-2017-1289",
    "CVE-2017-3509",
    "CVE-2017-3511",
    "CVE-2017-3512",
    "CVE-2017-3514",
    "CVE-2017-3533",
    "CVE-2017-3539",
    "CVE-2017-3544"
  );
  script_bugtraq_id(
    95131,
    97727,
    97729,
    97731,
    97737,
    97740,
    97745,
    97752,
    98401
  );

  script_name(english:"AIX Java Advisory : java_apr2017_advisory.asc (April 2017 CPU)");
  script_summary(english:"Checks the version of the Java package.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Java SDK installed on the remote AIX host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Java SDK installed on the remote AIX host is affected
by multiple vulnerabilities in the following subcomponents :

  - Multiple vulnerabilities exist in the zlib subcomponent
    that allow an unauthenticated, remote attacker to
    trigger denial of service conditions. (CVE-2016-9840,
    CVE-2016-9841, CVE-2016-9842, CVE-2016-9843)

  - An unspecified flaw exists in the XML subcomponent that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2017-1289)

  - An unspecified flaw exists in the Networking
    subcomponent that allows an unauthenticated, remote
    attacker to impact confidentiality and integrity.
    (CVE-2017-3509)

  - An unspecified flaw exists in the JCE subcomponent that
    allows a local attacker to gain elevated privileges.
    This vulnerability does not affect Java SE version 6.
    (CVE-2017-3511)

  - An unspecified flaw exists in the AWT subcomponent
    that allows an unauthenticated, remote attacker to
    execute arbitrary code. This vulnerability does not
    affect Java SE version 6. (CVE-2017-3512)

  - An unspecified flaw exists in the AWT subcomponent
    that allows an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2017-3514)

  - Multiple unspecified flaws exist in the Networking
    subcomponent that allow an unauthenticated, remote
    attacker to gain update, insert, or delete access to
    unauthorized data. (CVE-2017-3533, CVE-2017-3544)

  - An unspecified flaw exists in the Security subcomponent
    that allows an unauthenticated, remote attacker to gain
    update, insert, or delete access to unauthorized data.
    (CVE-2017-3539)");
  # https://aix.software.ibm.com/aix/efixes/security/java_apr2017_advisory.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d03f97b");
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
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?623d2c22");
  script_set_attribute(attribute:"solution", value:
"Fixes are available by version and can be downloaded from the IBM AIX
website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/21");
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

#Java6 6.0.0.645
if (aix_check_package(release:"5.3", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.644", fixpackagever:"6.0.0.645") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.644", fixpackagever:"6.0.0.645") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.644", fixpackagever:"6.0.0.645") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.644", fixpackagever:"6.0.0.645") > 0) flag++;
if (aix_check_package(release:"5.3", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.644", fixpackagever:"6.0.0.645") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.644", fixpackagever:"6.0.0.645") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.644", fixpackagever:"6.0.0.645") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.644", fixpackagever:"6.0.0.645") > 0) flag++;

#Java7 7.0.0.605
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.604", fixpackagever:"7.0.0.605") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.604", fixpackagever:"7.0.0.605") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.604", fixpackagever:"7.0.0.605") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.604", fixpackagever:"7.0.0.605") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.604", fixpackagever:"7.0.0.605") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.604", fixpackagever:"7.0.0.605") > 0) flag++;

#Java7.1 7.1.0.405
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.404", fixpackagever:"7.1.0.405") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.404", fixpackagever:"7.1.0.405") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.404", fixpackagever:"7.1.0.405") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.404", fixpackagever:"7.1.0.405") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.404", fixpackagever:"7.1.0.405") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.404", fixpackagever:"7.1.0.405") > 0) flag++;

#Java8.0 8.0.0.406
if (aix_check_package(release:"6.1", package:"Java8.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.405", fixpackagever:"8.0.0.406") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java8.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.405", fixpackagever:"8.0.0.406") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java8.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.405", fixpackagever:"8.0.0.406") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java8_64.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.405", fixpackagever:"8.0.0.406") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java8_64.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.405", fixpackagever:"8.0.0.406") > 0) flag++;
if (aix_check_package(release:"7.2", package:"Java8_64.sdk", minpackagever:"8.0.0.0", maxpackagever:"8.0.0.405", fixpackagever:"8.0.0.406") > 0) flag++;

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
