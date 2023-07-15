#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202101-29.
#
# The advisory text is Copyright (C) 2001-2022 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(145436);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2018-21010", "CVE-2019-12973", "CVE-2020-15389", "CVE-2020-27814", "CVE-2020-27841", "CVE-2020-27842", "CVE-2020-27843", "CVE-2020-27844", "CVE-2020-27845");
  script_xref(name:"GLSA", value:"202101-29");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"GLSA-202101-29 : OpenJPEG: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-202101-29
(OpenJPEG: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in OpenJPEG. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    Please review the referenced CVE identifiers for details.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/202101-29"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All OpenJPEG 2 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/openjpeg-2.4.0:2'
    Gentoo has discontinued support OpenJPEG 1.x and any dependent packages
      should now be using OpenJPEG 2 or have dropped support for the library.
      We recommend that users unmerge OpenJPEG 1.x:
      # emerge --unmerge 'media-libs/openjpeg:1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27844");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openjpeg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"media-libs/openjpeg", unaffected:make_list("ge 2.4.0"), vulnerable:make_list("lt 2.4.0", "lt 1.5.2-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenJPEG");
}
