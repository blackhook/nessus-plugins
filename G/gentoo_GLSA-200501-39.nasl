#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200501-39.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16430);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2005-0075", "CVE-2005-0103", "CVE-2005-0104");
  script_xref(name:"GLSA", value:"200501-39");

  script_name(english:"GLSA-200501-39 : SquirrelMail: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200501-39
(SquirrelMail: Multiple vulnerabilities)

    SquirrelMail fails to properly sanitize certain strings when
    decoding specially crafted strings, which can lead to PHP file
    inclusion and XSS.
    Insufficient checking of incoming URLs
    in prefs.php (CAN-2005-0075) and in webmail.php (CAN-2005-0103).
    Insufficient escaping of integers in webmail.php
    (CAN-2005-0104).
  
Impact :

    By sending a specially crafted URL, an attacker can execute
    arbitrary code from the local system with the permissions of the web
    server. Furthermore by enticing a user to load a specially crafted URL,
    it is possible to display arbitrary remote web pages in Squirrelmail's
    frameset and execute arbitrary scripts running in the context of the
    victim's browser. This could lead to a compromise of the user's webmail
    account, cookie theft, etc.
  
Workaround :

    The arbitrary code execution is only possible with
    'register_globals' set to 'On'. Gentoo ships PHP with
    'register_globals' set to 'Off' by default. There are no known
    workarounds for the other issues at this time."
  );
  # http://sourceforge.net/mailarchive/message.php?msg_id=10628451
  script_set_attribute(
    attribute:"see_also",
    value:"https://sourceforge.net/p/linux-usb/mailman/message/10628451/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200501-39"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All SquirrelMail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/squirrelmail-1.4.4'
    Note: Users with the vhosts USE flag set should manually use
    webapp-config to finalize the update."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"mail-client/squirrelmail", unaffected:make_list("ge 1.4.4"), vulnerable:make_list("le 1.4.3a-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SquirrelMail");
}
