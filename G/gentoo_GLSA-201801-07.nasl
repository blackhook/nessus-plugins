#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201801-07.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(105633);
  script_version("3.5");
  script_cvs_date("Date: 2019/04/05 23:25:06");

  script_cve_id("CVE-2017-14482");
  script_xref(name:"GLSA", value:"201801-07");

  script_name(english:"GLSA-201801-07 : GNU Emacs: Command injection");
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
"The remote host is affected by the vulnerability described in GLSA-201801-07
(GNU Emacs: Command injection)

    A command injection flaw within the Emacs &ldquo;enriched mode&rdquo; handling
      has been discovered.
  
Impact :

    A remote attacker, by enticing a user to open a specially crafted file,
      could execute arbitrary commands with the privileges of process.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201801-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All GNU Emacs 23.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-editors/emacs-23.4-r16:23'
    All GNU Emacs 24.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-editors/emacs-24.5-r4:24'
    All GNU Emacs 25.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-editors/emacs-25.2-r1:25'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:emacs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"app-editors/emacs", unaffected:make_list("ge 23.4-r16", "ge 24.5-r4", "ge 25.2-r1"), vulnerable:make_list("lt 23.4-r16", "lt 24.5-r4", "lt 25.2-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GNU Emacs");
}
