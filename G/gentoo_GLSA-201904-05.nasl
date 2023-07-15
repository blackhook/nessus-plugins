#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201904-05.
#
# The advisory text is Copyright (C) 2001-2020 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(123579);
  script_version("1.2");
  script_cvs_date("Date: 2020/01/27");

  script_cve_id("CVE-2017-18285");
  script_xref(name:"GLSA", value:"201904-05");

  script_name(english:"GLSA-201904-05 : BURP: Root privilege escalation");
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
"The remote host is affected by the vulnerability described in GLSA-201904-05
(BURP: Root privilege escalation)

    It was discovered that Gentoo&rsquo;s BURP ebuild does not properly set
      permissions or place the pid file in a safe directory. Additionally, the
      first set of patches did not completely address this.  As such, a
      revision has been made available that addresses all concerns of the
      initial report.
  
Impact :

    A local attacker could escalate privileges.
  
Workaround :

    Users should ensure the proper permissions are set as discussed in the
      referenced bugs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201904-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All BURP users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-backup/burp-2.1.32-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:burp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"app-backup/burp", unaffected:make_list("ge 2.1.32-r1"), vulnerable:make_list("lt 2.1.32-r1"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:qpkg_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "BURP");
}
