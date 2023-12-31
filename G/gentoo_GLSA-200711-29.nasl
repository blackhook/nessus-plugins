#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200711-29.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(28318);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2007-4572", "CVE-2007-5398");
  script_xref(name:"GLSA", value:"200711-29");

  script_name(english:"GLSA-200711-29 : Samba: Execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200711-29
(Samba: Execution of arbitrary code)

    Two vulnerabilities have been reported in nmbd. Alin Rad Pop (Secunia
    Research) discovered a boundary checking error in the
    reply_netbios_packet() function which could lead to a stack-based
    buffer overflow (CVE-2007-5398). The Samba developers discovered a
    boundary error when processing GETDC logon requests also leading to a
    buffer overflow (CVE-2007-4572).
  
Impact :

    To exploit the first vulnerability, a remote unauthenticated attacker
    could send specially crafted WINS 'Name Registration' requests followed
    by a WINS 'Name Query' request. This might lead to execution of
    arbitrary code with elevated privileges. Note that this vulnerability
    is exploitable only when WINS server support is enabled in Samba. The
    second vulnerability could be exploited by sending specially crafted
    'GETDC' mailslot requests, but requires Samba to be configured as a
    Primary or Backup Domain Controller. It is not believed the be
    exploitable to execute arbitrary code.
  
Workaround :

    To work around the first vulnerability, disable WINS support in Samba
    by setting 'wins support = no' in the 'global' section of your
    smb.conf and restart Samba."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200711-29"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Samba users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-fs/samba-3.0.27a'
    The first vulnerability (CVE-2007-5398) was already fixed in Samba
    3.0.26a-r2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-fs/samba", unaffected:make_list("ge 3.0.27a"), vulnerable:make_list("lt 3.0.27a"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Samba");
}
