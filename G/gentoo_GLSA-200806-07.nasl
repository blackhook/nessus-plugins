#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200806-07.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(33243);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2008-1377", "CVE-2008-1379", "CVE-2008-2360", "CVE-2008-2361", "CVE-2008-2362");
  script_xref(name:"GLSA", value:"200806-07");

  script_name(english:"GLSA-200806-07 : X.Org X server: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200806-07
(X.Org X server: Multiple vulnerabilities)

    Regenrecht reported multiple vulnerabilities in various X server
    extensions via iDefense:
    The
    SProcSecurityGenerateAuthorization() and SProcRecordCreateContext()
    functions of the RECORD and Security extensions are lacking proper
    parameter validation (CVE-2008-1377).
    An integer overflow is
    possible in the function ShmPutImage() of the MIT-SHM extension
    (CVE-2008-1379).
    The RENDER extension contains several
    possible integer overflows in the AllocateGlyph() function
    (CVE-2008-2360) which could possibly lead to a heap-based buffer
    overflow. Further possible integer overflows have been found in the
    ProcRenderCreateCursor() function (CVE-2008-2361) as well as in the
    SProcRenderCreateLinearGradient(), SProcRenderCreateRadialGradient()
    and SProcRenderCreateConicalGradient() functions (CVE-2008-2362).
  
Impact :

    Exploitation of these vulnerabilities could possibly lead to the remote
    execution of arbitrary code with root privileges, if the server is
    running as root, which is the default. It is also possible to crash the
    server by making use of these vulnerabilities.
  
Workaround :

    It is possible to avoid these vulnerabilities by disabling the affected
    server extensions. Therefore edit the configuration file
    (/etc/X11/xorg.conf) to contain the following in the appropriate
    places:
      Section 'Extensions'
    	Option 'MIT-SHM' 'disable'
    	Option 'RENDER' 'disable'
    	Option 'SECURITY' 'disable'
      EndSection
      Section 'Module'
       Disable 'record'
      EndSection"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200806-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All X.org X Server users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-base/xorg-server-1.3.0.0-r6'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xorg-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"x11-base/xorg-server", unaffected:make_list("ge 1.3.0.0-r6"), vulnerable:make_list("lt 1.3.0.0-r6"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "X.Org X server");
}
