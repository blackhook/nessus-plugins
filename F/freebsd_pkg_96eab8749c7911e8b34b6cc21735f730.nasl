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

include("compat.inc");

if (description)
{
  script_id(111656);
  script_version("1.4");
  script_cvs_date("Date: 2018/11/10 11:49:47");

  script_cve_id("CVE-2018-10915", "CVE-2018-10925");

  script_name(english:"FreeBSD : PostgreSQL -- two vulnerabilities (96eab874-9c79-11e8-b34b-6cc21735f730)");
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

CVE-2018-10915: Certain host connection parameters defeat client-side
security defenses

libpq, the client connection API for PostgreSQL that is also used by
other connection libraries, had an internal issue where it did not
reset all of its connection state variables when attempting to
reconnect. In particular, the state variable that determined whether
or not a password is needed for a connection would not be reset, which
could allow users of features requiring libpq, such as the 'dblink' or
'postgres_fdw' extensions, to login to servers they should not be able
to access.

CVE-2018-10925: Memory disclosure and missing authorization in `INSERT
... ON CONFLICT DO UPDATE`

An attacker able to issue CREATE TABLE can read arbitrary bytes of
server memory using an upsert (`INSERT ... ON CONFLICT DO UPDATE`)
query. By default, any user can exploit that. A user that has specific
INSERT privileges and an UPDATE privilege on at least one column in a
given table can also update other columns using a view and an upsert
query."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/about/news/1878/"
  );
  # https://vuxml.freebsd.org/freebsd/96eab874-9c79-11e8-b34b-6cc21735f730.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d981a7b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql10-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql93-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql94-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql95-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql96-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"postgresql10-server<10.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql96-server<9.6.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql95-server<9.5.14")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql94-server<9.4.19")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql93-server<9.3.24")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
