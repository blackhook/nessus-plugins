#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202105-01.
#
# The advisory text is Copyright (C) 2001-2022 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149277);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/06");

  script_cve_id("CVE-2020-28007", "CVE-2020-28008", "CVE-2020-28009", "CVE-2020-28010", "CVE-2020-28011", "CVE-2020-28012", "CVE-2020-28013", "CVE-2020-28014", "CVE-2020-28015", "CVE-2020-28016", "CVE-2020-28017", "CVE-2020-28018", "CVE-2020-28019", "CVE-2020-28020", "CVE-2020-28021", "CVE-2020-28022", "CVE-2020-28023", "CVE-2020-28024", "CVE-2020-28025", "CVE-2020-28026", "CVE-2021-27216");
  script_xref(name:"GLSA", value:"202105-01");
  script_xref(name:"IAVA", value:"2021-A-0216-S");

  script_name(english:"GLSA-202105-01 : Exim: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-202105-01
(Exim: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Exim. Please review the
      CVE identifiers referenced below for details.
  
Impact :

    A remote attacker, by connecting to the SMTP listener daemon, could
      possibly execute arbitrary code with the privileges of the process or
      cause a Denial of Service condition. Furthermore, a local attacker could
      perform symlink attacks to overwrite arbitrary files with the privileges
      of the user running the application or escalate privileges.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/202105-01"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All Exim users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=mail-mta/exim-4.94.2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28026");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:exim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"mail-mta/exim", unaffected:make_list("ge 4.94.2"), vulnerable:make_list("lt 4.94.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Exim");
}
