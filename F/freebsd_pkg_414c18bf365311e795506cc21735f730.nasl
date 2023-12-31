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
  script_id(100141);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-5423", "CVE-2016-5424");

  script_name(english:"FreeBSD : PostgreSQL vulnerabilities (414c18bf-3653-11e7-9550-6cc21735f730)");
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
"The PostgreSQL project reports :

Security Fixes nested CASE expressions + database and role names with
embedded special characters

- CVE-2017-7484: selectivity estimators bypass SELECT privilege
checks.

- CVE-2017-7485: libpq ignores PGREQUIRESSL environment variable

- CVE-2017-7486: pg_user_mappings view discloses foreign server
passwords. This applies to new databases, see the release notes for
the procedure to apply the fix to an existing database."
  );
  # https://vuxml.freebsd.org/freebsd/414c18bf-3653-11e7-9550-6cc21735f730.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d375895b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql92-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql92-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql93-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql93-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql94-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql94-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql95-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql95-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql96-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql96-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/12");
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

if (pkg_test(save_report:TRUE, pkg:"postgresql92-client>=9.2.0<9.2.20")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql93-client>=9.3.0<9.3.16")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql94-client>=9.4.0<9.4.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql95-client>=9.5.0<9.5.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql96-client>=9.6.0<9.6.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql92-server>=9.2.0<9.2.20")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql93-server>=9.3.0<9.3.16")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql94-server>=9.4.0<9.4.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql95-server>=9.5.0<9.5.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql96-server>=9.6.0<9.6.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
