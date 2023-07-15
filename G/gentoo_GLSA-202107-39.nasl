#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202107-39.
#
# The advisory text is Copyright (C) 2001-2022 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(156985);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/14");

  script_cve_id("CVE-2013-0248", "CVE-2014-0050", "CVE-2016-3092");
  script_xref(name:"GLSA", value:"202107-39");

  script_name(english:"GLSA-202107-39 : Apache Commons FileUpload: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-202107-39
(Apache Commons FileUpload: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Apache Commons
      FileUpload. Please review the CVE identifiers referenced below for
      details.
  
Impact :

    Please review the referenced CVE identifiers for details.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/202107-39"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Gentoo has discontinued support for Apache Commons FileUpload. We
      recommend that users unmerge it:
      # emerge --ask --depclean 'dev-java/commons-fileupload'
    NOTE: The Gentoo developer(s) maintaining Apache Commons FileUpload have
      discontinued support at this time. It may be possible that a new Gentoo
      developer will update Apache Commons FileUpload at a later date. We do
      not have a suggestion for a replacement at this time."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3092");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:commons-fileupload");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"dev-java/commons-fileupload", unaffected:make_list(), vulnerable:make_list("le 1.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Apache Commons FileUpload");
}
