#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202105-27.
#
# The advisory text is Copyright (C) 2001-2022 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(156994);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2019-2938", "CVE-2019-2974", "CVE-2020-14539", "CVE-2020-14540", "CVE-2020-14547", "CVE-2020-14550", "CVE-2020-14553", "CVE-2020-14559", "CVE-2020-14564", "CVE-2020-14567", "CVE-2020-14568", "CVE-2020-14575", "CVE-2020-14576", "CVE-2020-14586", "CVE-2020-14591", "CVE-2020-14597", "CVE-2020-14614", "CVE-2020-14619", "CVE-2020-14620", "CVE-2020-14623", "CVE-2020-14624", "CVE-2020-14626", "CVE-2020-14631", "CVE-2020-14632", "CVE-2020-14633", "CVE-2020-14634", "CVE-2020-14641", "CVE-2020-14643", "CVE-2020-14651", "CVE-2020-14654", "CVE-2020-14656", "CVE-2020-14663", "CVE-2020-14672", "CVE-2020-14678", "CVE-2020-14680", "CVE-2020-14697", "CVE-2020-14702", "CVE-2020-14725", "CVE-2020-14760", "CVE-2020-14765", "CVE-2020-14769", "CVE-2020-14771", "CVE-2020-14773", "CVE-2020-14775", "CVE-2020-14776", "CVE-2020-14777", "CVE-2020-14785", "CVE-2020-14786", "CVE-2020-14789", "CVE-2020-14790", "CVE-2020-14791", "CVE-2020-14793", "CVE-2020-14794", "CVE-2020-14799", "CVE-2020-14800", "CVE-2020-14804", "CVE-2020-14809", "CVE-2020-14812", "CVE-2020-14814", "CVE-2020-14821", "CVE-2020-14827", "CVE-2020-14828", "CVE-2020-14829", "CVE-2020-14830", "CVE-2020-14836", "CVE-2020-14837", "CVE-2020-14838", "CVE-2020-14839", "CVE-2020-14844", "CVE-2020-14845", "CVE-2020-14846", "CVE-2020-14848", "CVE-2020-14852", "CVE-2020-14853", "CVE-2020-14860", "CVE-2020-14861", "CVE-2020-14866", "CVE-2020-14867", "CVE-2020-14868", "CVE-2020-14869", "CVE-2020-14870", "CVE-2020-14873", "CVE-2020-14878", "CVE-2020-14888", "CVE-2020-14891", "CVE-2020-14893", "CVE-2020-2570", "CVE-2020-2572", "CVE-2020-2573", "CVE-2020-2574", "CVE-2020-2577", "CVE-2020-2579", "CVE-2020-2580", "CVE-2020-2584", "CVE-2020-2588", "CVE-2020-2589", "CVE-2020-2627", "CVE-2020-2660", "CVE-2020-2679", "CVE-2020-2686", "CVE-2020-2694", "CVE-2020-2752", "CVE-2020-2759", "CVE-2020-2760", "CVE-2020-2761", "CVE-2020-2762", "CVE-2020-2763", "CVE-2020-2765", "CVE-2020-2768", "CVE-2020-2770", "CVE-2020-2774", "CVE-2020-2779", "CVE-2020-2780", "CVE-2020-2790", "CVE-2020-2804", "CVE-2020-2806", "CVE-2020-2812", "CVE-2020-2814", "CVE-2020-2853", "CVE-2020-2875", "CVE-2020-2892", "CVE-2020-2893", "CVE-2020-2895", "CVE-2020-2896", "CVE-2020-2897", "CVE-2020-2898", "CVE-2020-2901", "CVE-2020-2903", "CVE-2020-2904", "CVE-2020-2921", "CVE-2020-2922", "CVE-2020-2923", "CVE-2020-2924", "CVE-2020-2925", "CVE-2020-2926", "CVE-2020-2928", "CVE-2020-2930", "CVE-2020-2933", "CVE-2020-2934", "CVE-2021-1998", "CVE-2021-2001", "CVE-2021-2002", "CVE-2021-2006", "CVE-2021-2007", "CVE-2021-2009", "CVE-2021-2010", "CVE-2021-2011", "CVE-2021-2012", "CVE-2021-2014", "CVE-2021-2016", "CVE-2021-2019", "CVE-2021-2020", "CVE-2021-2021", "CVE-2021-2022", "CVE-2021-2024", "CVE-2021-2028", "CVE-2021-2030", "CVE-2021-2031", "CVE-2021-2032", "CVE-2021-2036", "CVE-2021-2038", "CVE-2021-2042", "CVE-2021-2046", "CVE-2021-2048", "CVE-2021-2055", "CVE-2021-2056", "CVE-2021-2058", "CVE-2021-2060", "CVE-2021-2061", "CVE-2021-2065", "CVE-2021-2070", "CVE-2021-2072", "CVE-2021-2076", "CVE-2021-2081", "CVE-2021-2087", "CVE-2021-2088", "CVE-2021-2122", "CVE-2021-2154", "CVE-2021-2166", "CVE-2021-2180");
  script_xref(name:"GLSA", value:"202105-27");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"GLSA-202105-27 : MySQL: Multiple vulnerabilities");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is affected by the vulnerability described in GLSA-202105-27
(MySQL: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in MySQL. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    An attacker could possibly execute arbitrary code with the privileges of
      the process, escalate privileges, gain access to critical data or
      complete access to all MySQL server accessible data, or cause a Denial of
      Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/202105-27"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All MySQL users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/mysql-5.7.34'
    All mysql users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/mysql-8.0.24'"
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14878");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mysql-connector-c");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"dev-db/mysql", unaffected:make_list("ge 5.7.34", "ge 8.0.24"), vulnerable:make_list("lt 8.0.24"))) flag++;
if (qpkg_check(package:"dev-db/mysql-connector-c", unaffected:make_list("ge 8.0.24"), vulnerable:make_list("lt 8.0.24"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MySQL");
}
