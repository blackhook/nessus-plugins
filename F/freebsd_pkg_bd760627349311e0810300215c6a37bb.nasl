#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2018 Jacques Vidrine and contributors
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
  script_id(51929);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_name(english:"FreeBSD : django -- multiple vulnerabilities (bd760627-3493-11e0-8103-00215c6a37bb)");
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
"Django project reports :

Today the Django team is issuing multiple releases -- Django 1.2.5 and
Django 1.1.4 -- to remedy three security issues reported to us. All
users of affected versions of Django are urged to upgrade immediately."
  );
  # http://www.djangoproject.com/weblog/2011/feb/08/security/
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.djangoproject.com/weblog/2011/feb/08/security/"
  );
  # https://vuxml.freebsd.org/freebsd/bd760627-3493-11e0-8103-00215c6a37bb.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d1177f6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py23-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py23-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py24-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py24-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py25-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py25-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py26-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py26-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py30-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py30-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py31-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py31-django-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"py23-django>1.2<1.2.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py23-django>1.1<1.1.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py24-django>1.2<1.2.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py24-django>1.1<1.1.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py25-django>1.2<1.2.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py25-django>1.1<1.1.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py26-django>1.2<1.2.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py26-django>1.1<1.1.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django>1.2<1.2.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django>1.1<1.1.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py30-django>1.2<1.2.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py30-django>1.1<1.1.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py31-django>1.2<1.2.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py31-django>1.1<1.1.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py23-django-devel<15470,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py24-django-devel<15470,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py25-django-devel<15470,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py26-django-devel<15470,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django-devel<15470,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py30-django-devel<15470,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py31-django-devel<15470,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
