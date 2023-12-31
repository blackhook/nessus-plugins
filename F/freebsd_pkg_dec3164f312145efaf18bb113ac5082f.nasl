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
  script_id(82893);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2015-3414", "CVE-2015-3415", "CVE-2015-3416");

  script_name(english:"FreeBSD : sqlite -- multiple vulnerabilities (dec3164f-3121-45ef-af18-bb113ac5082f)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"NVD reports :

SQLite before 3.8.9 does not properly implement the dequoting of
collation-sequence names, which allows context-dependent attackers to
cause a denial of service (uninitialized memory access and application
crash) or possibly have unspecified other impact via a crafted COLLATE
clause, as demonstrated by COLLATE'''''''' at the end of a SELECT
statement.

The sqlite3VdbeExec function in vdbe.c in SQLite before 3.8.9 does not
properly implement comparison operators, which allows
context-dependent attackers to cause a denial of service (invalid free
operation) or possibly have unspecified other impact via a crafted
CHECK clause, as demonstrated by CHECK(0&O>O) in a CREATE TABLE
statement.

The sqlite3VXPrintf function in printf.c in SQLite before 3.8.9 does
not properly handle precision and width values during floating-point
conversions, which allows context-dependent attackers to cause a
denial of service (integer overflow and stack-based buffer overflow)
or possibly have unspecified other impact via large integers in a
crafted printf function call in a SELECT statement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.sqlite.org/src/info/eddc05e7bb31fae7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.sqlite.org/src/info/02e3c88fbf6abdcf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.sqlite.org/src/info/c494171f77dc2e5e"
  );
  # http://seclists.org/fulldisclosure/2015/Apr/31
  script_set_attribute(
    attribute:"see_also",
    value:"https://seclists.org/fulldisclosure/2015/Apr/31"
  );
  # https://vuxml.freebsd.org/freebsd/dec3164f-3121-45ef-af18-bb113ac5082f.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?972e9809"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:sqlite3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"sqlite3<3.8.9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
