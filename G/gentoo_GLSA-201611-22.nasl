#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201611-22.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(95421);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-8865", "CVE-2016-3074", "CVE-2016-4071", "CVE-2016-4072", "CVE-2016-4073", "CVE-2016-4537", "CVE-2016-4538", "CVE-2016-4539", "CVE-2016-4540", "CVE-2016-4541", "CVE-2016-4542", "CVE-2016-4543", "CVE-2016-4544", "CVE-2016-5385", "CVE-2016-6289", "CVE-2016-6290", "CVE-2016-6291", "CVE-2016-6292", "CVE-2016-6294", "CVE-2016-6295", "CVE-2016-6296", "CVE-2016-6297", "CVE-2016-7124", "CVE-2016-7125", "CVE-2016-7126", "CVE-2016-7127", "CVE-2016-7128", "CVE-2016-7129", "CVE-2016-7130", "CVE-2016-7131", "CVE-2016-7132", "CVE-2016-7133", "CVE-2016-7134", "CVE-2016-7411", "CVE-2016-7412", "CVE-2016-7413", "CVE-2016-7414", "CVE-2016-7416", "CVE-2016-7417", "CVE-2016-7418");
  script_xref(name:"GLSA", value:"201611-22");

  script_name(english:"GLSA-201611-22 : PHP: Multiple vulnerabilities (httpoxy)");
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
"The remote host is affected by the vulnerability described in GLSA-201611-22
(PHP: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in PHP. Please review the
      CVE identifiers referenced below for details.
  
Impact :

    An attacker can possibly execute arbitrary code or create a Denial of
      Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201611-22"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PHP users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev=lang/php-5.6.28'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/30");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"dev-lang/php", unaffected:make_list("ge 5.6.28"), vulnerable:make_list("lt 5.6.28"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PHP");
}
