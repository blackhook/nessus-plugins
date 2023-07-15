#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202005-11.
#
# The advisory text is Copyright (C) 2001-2020 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(136641);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2019-19721");
  script_xref(name:"GLSA", value:"202005-11");
  script_xref(name:"IAVB", value:"2020-B-0025-S");

  script_name(english:"GLSA-202005-11 : VLC: Buffer overflow");
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
"The remote host is affected by the vulnerability described in GLSA-202005-11
(VLC: Buffer overflow)

    A buffer overflow in DecodeBlock in sdl_image.c was discovered.
  
Impact :

    A remote user could craft a specifically crafted image file that could
      execute arbitrary code or cause denial of service.
  
Workaround :

    The user should refrain from opening files from untrusted third parties
      or accessing untrusted remote sites (or disable the VLC browser plugins),
      until they upgrade."
  );
  # https://git.videolan.org/?p=vlc/vlc-3.0.git;a=commit;h=72afe7ebd8305bf4f5360293b8621cde52ec506b
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64105146"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.videolan.org/security/sb-vlc309.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/202005-11"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All VLC users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-video/vlc-3.0.10'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19721");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vlc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"media-video/vlc", unaffected:make_list("ge 3.0.10"), vulnerable:make_list("lt 3.0.10"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "VLC");
}
