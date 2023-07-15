#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201908-03.
#
# The advisory text is Copyright (C) 2001-2020 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(127561);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/06");

  script_cve_id("CVE-2017-1000050", "CVE-2017-13745", "CVE-2017-13746", "CVE-2017-13747", "CVE-2017-13748", "CVE-2017-13749", "CVE-2017-13750", "CVE-2017-13751", "CVE-2017-13752", "CVE-2017-13753", "CVE-2017-14132", "CVE-2017-14229", "CVE-2017-5503", "CVE-2017-5504", "CVE-2017-5505", "CVE-2017-6851", "CVE-2017-6852", "CVE-2017-9782", "CVE-2018-18873", "CVE-2018-20584", "CVE-2018-9055", "CVE-2018-9154");
  script_xref(name:"GLSA", value:"201908-03");

  script_name(english:"GLSA-201908-03 : JasPer: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201908-03
(JasPer: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in JasPer. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    Please review the referenced CVE identifiers for details.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201908-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"JasPer is no longer maintained upstream and contains many
      vulnerabilities which remain unaddressed. Gentoo users are advised to
      unmerge this package.
      # emerge --unmerge media-libs/jasper"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:jasper");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
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

if (qpkg_check(package:"media-libs/jasper", unaffected:make_list(), vulnerable:make_list("le 2.0.16"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "JasPer");
}
