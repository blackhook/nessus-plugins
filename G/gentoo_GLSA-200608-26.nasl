#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200608-26.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22288);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2006-4330", "CVE-2006-4331", "CVE-2006-4332", "CVE-2006-4333");
  script_xref(name:"GLSA", value:"200608-26");

  script_name(english:"GLSA-200608-26 : Wireshark: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200608-26
(Wireshark: Multiple vulnerabilities)

    The following vulnerabilities have been discovered in Wireshark.
    Firstly, if the IPsec ESP parser is used it is susceptible to
    off-by-one errors, this parser is disabled by default; secondly, the
    SCSI dissector is vulnerable to an unspecified crash; and finally, the
    Q.2931 dissector of the SSCOP payload may use all the available memory
    if a port range is configured. By default, no port ranges are
    configured.
  
Impact :

    An attacker might be able to exploit these vulnerabilities, resulting
    in a crash or the execution of arbitrary code with the permissions of
    the user running Wireshark, possibly the root user.
  
Workaround :

    Disable the SCSI and Q.2931 dissectors with the 'Analyse' and 'Enabled
    protocols' menus. Make sure the ESP decryption is disabled, with the
    'Edit -> Preferences -> Protocols -> ESP' menu."
  );
  # http://www.wireshark.org/security/wnpa-sec-2006-02.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2006-02.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200608-26"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Wireshark users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-analyzer/wireshark-0.99.3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"net-analyzer/wireshark", unaffected:make_list("ge 0.99.3"), vulnerable:make_list("lt 0.99.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Wireshark");
}
