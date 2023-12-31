#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200408-17.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14573);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2004-0792");
  script_xref(name:"GLSA", value:"200408-17");

  script_name(english:"GLSA-200408-17 : rsync: Potential information leakage");
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
"The remote host is affected by the vulnerability described in GLSA-200408-17
(rsync: Potential information leakage)

    The paths sent by the rsync client are not checked thoroughly enough.
    It does not affect the normal send/receive filenames that specify what
    files should be transferred. It does affect certain option paths that
    cause auxiliary files to be read or written.
  
Impact :

    When rsyncd is used without chroot ('use chroot = false' in the
    rsyncd.conf file), this vulnerability could allow the listing of
    arbitrary files outside module's path and allow file overwriting
    outside module's path on rsync server configurations that allows
    uploading. Both possibilities are exposed only when chroot option is
    disabled.
  
Workaround :

    You should never set the rsync daemon to run with 'use chroot = false'."
  );
  # http://samba.org/rsync/#security_aug04
  script_set_attribute(
    attribute:"see_also",
    value:"https://rsync.samba.org/#security_aug04"
  );
  # http://lists.samba.org/archive/rsync-announce/2004/000017.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.samba.org/archive/rsync-announce/2004/000017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200408-17"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users should update to the latest version of the rsync package.
    # emerge sync
    # emerge -pv '>=net-misc/rsync-2.6.0-r3'
    # emerge '>=net-misc/rsync-2.6.0-r3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rsync");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"net-misc/rsync", unaffected:make_list("ge 2.6.0-r3"), vulnerable:make_list("le 2.6.0-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rsync");
}
