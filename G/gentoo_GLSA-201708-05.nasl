#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201708-05.
#
# The advisory text is Copyright (C) 2001-2020 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102617);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2012-6706");
  script_xref(name:"GLSA", value:"201708-05");

  script_name(english:"GLSA-201708-05 : RAR and UnRAR: User-assisted execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-201708-05
(RAR and UnRAR: User-assisted execution of arbitrary code)

    A VMSF_DELTA memory corruption was discovered in which an integer
      overflow can be caused in DataSize+CurChannel. The result is a negative
      value of the &ldquo;DestPos&rdquo; variable which allows writing out of bounds
      when setting Mem[DestPos].
  
Impact :

    A remote attacker, by enticing a user to open a specially crafted
      archive, could execute arbitrary code with the privileges of the process.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201708-05"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All RAR users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-arch/rar-5.5.0_beta4_p20170628'
    All UnRAR users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-arch/unrar-5.5.5'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:unrar");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/21");
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

if (qpkg_check(package:"app-arch/rar", unaffected:make_list("ge 5.5.0_beta4_p20170628"), vulnerable:make_list("lt 5.5.0_beta4_p20170628"))) flag++;
if (qpkg_check(package:"app-arch/unrar", unaffected:make_list("ge 5.5.5"), vulnerable:make_list("lt 5.5.5"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "RAR and UnRAR");
}
