#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202006-21.
#
# The advisory text is Copyright (C) 2001-2022 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(137458);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-9484");
  script_xref(name:"GLSA", value:"202006-21");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"GLSA-202006-21 : Apache Tomcat: Remote code execution");
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
"The remote host is affected by the vulnerability described in GLSA-202006-21
(Apache Tomcat: Remote code execution)

    Apache Tomcat improperly handles deserialization of files under specific
      circumstances.
  
Impact :

    A remote attacker could possibly execute arbitrary code with the
      privileges of the process, or cause a Denial of Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  # https://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.104
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d383947b"
  );
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.55
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9502c510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/202006-21"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All Apache Tomcat 7.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-servers/tomcat-7.0.104'
    All Apache Tomcat 8.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-servers/tomcat-8.5.55'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:tomcat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"www-servers/tomcat", unaffected:make_list("ge 7.0.104", "ge 8.5.55"), vulnerable:make_list("lt 7.0.104", "lt 8.5.55"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Apache Tomcat");
}
