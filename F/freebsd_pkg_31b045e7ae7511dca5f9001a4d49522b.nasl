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
  script_id(29771);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2007-6520", "CVE-2007-6521", "CVE-2007-6522", "CVE-2007-6524");

  script_name(english:"FreeBSD : opera -- multiple vulnerabilities (31b045e7-ae75-11dc-a5f9-001a4d49522b)");
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
"Opera Software ASA reports about multiple security fixes :

- Fixed an issue where plug-ins could be used to allow cross domain
scripting, as reported by David Bloom. Details will be disclosed at a
later date.

- Fixed an issue with TLS certificates that could be used to execute
arbitrary code, as reported by Alexander Klink (Cynops GmbH). Details
will be disclosed at a later date.

- Rich text editing can no longer be used to allow cross domain
scripting, as reported by David Bloom. See our advisory.

- Prevented bitmaps from revealing random data from memory, as
reported by Gynvael Coldwind. Details will be disclosed at a later
date."
  );
  # http://www.opera.com/docs/changelogs/freebsd/925/
  script_set_attribute(
    attribute:"see_also",
    value:"https://help.opera.com/en/latest/"
  );
  # http://www.opera.com/support/search/view/875/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?727499ab"
  );
  # https://vuxml.freebsd.org/freebsd/31b045e7-ae75-11dc-a5f9-001a4d49522b.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97c5c7bf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(79, 200, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-opera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:opera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:opera-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"opera<9.25")) flag++;
if (pkg_test(save_report:TRUE, pkg:"opera-devel<9.25")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-opera<9.25")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
