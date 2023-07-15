#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201701-10.
#
# The advisory text is Copyright (C) 2001-2020 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96241);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-8833", "CVE-2016-2851");
  script_xref(name:"GLSA", value:"201701-10");

  script_name(english:"GLSA-201701-10 : libotr, Pidgin OTR: Remote execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-201701-10
(libotr, Pidgin OTR: Remote execution of arbitrary code)

    Multiple vulnerabilities exist in both libotr and Pidgin OTR. Please
      review the CVE identifiers for more information.
  
Impact :

    A remote attacker could send a specially crafted message, possibly
      resulting in the execution of arbitrary code with the privileges of the
      process, or cause a Denial of Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201701-10"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All libotr users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-libs/libotr-4.1.1'
    All Pidgin OTR users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-plugins/pidgin-otr-4.0.2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libotr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pidgin-otr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"net-libs/libotr", unaffected:make_list("ge 4.1.1"), vulnerable:make_list("lt 4.1.1"))) flag++;
if (qpkg_check(package:"x11-plugins/pidgin-otr", unaffected:make_list("ge 4.0.2"), vulnerable:make_list("lt 4.0.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libotr / Pidgin OTR");
}
