#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2019 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103953);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-11368", "CVE-2017-11462");

  script_name(english:"FreeBSD : krb5 -- Multiple vulnerabilities (3f3837cc-48fb-4414-aa46-5b1c23c9feae)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MIT reports :

CVE-2017-11368 :

In MIT krb5 1.7 and later, an authenticated attacker can cause an
assertion failure in krb5kdc by sending an invalid S4U2Self or
S4U2Proxy request.

CVE-2017-11462 :

RFC 2744 permits a GSS-API implementation to delete an existing
security context on a second or subsequent call to
gss_init_sec_context() or gss_accept_sec_context() if the call results
in an error. This API behavior has been found to be dangerous, leading
to the possibility of memory errors in some callers. For safety,
GSS-API implementations should instead preserve existing security
contexts on error until the caller deletes them.

All versions of MIT krb5 prior to this change may delete acceptor
contexts on error. Versions 1.13.4 through 1.13.7, 1.14.1 through
1.14.5, and 1.15 through 1.15.1 may also delete initiator contexts on
error."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://krbdev.mit.edu/rt/Ticket/Display.html?id=8599"
  );
  # https://github.com/krb5/krb5/commit/ffb35baac6981f9e8914f8f3bffd37f284b85970
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?329bbed6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://krbdev.mit.edu/rt/Ticket/Display.html?id=8598"
  );
  # https://github.com/krb5/krb5/commit/56f7b1bc95a2a3eeb420e069e7655fb181ade5cf
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?950727d9"
  );
  # https://vuxml.freebsd.org/freebsd/3f3837cc-48fb-4414-aa46-5b1c23c9feae.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f2d2817"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:krb5-113");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:krb5-114");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:krb5-115");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"krb5<1.14.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"krb5>=1.15<1.15.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"krb5-devel<1.14.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"krb5-devel>=1.15<1.15.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"krb5-115<1.15.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"krb5-114<1.14.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"krb5-113<1.14.6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
