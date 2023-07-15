#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2020 Jacques Vidrine and contributors
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
  script_id(133436);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/05");

  script_cve_id("CVE-2020-2574");

  script_name(english:"FreeBSD : MariaDB -- Vulnerability in C API (cb0183bb-45f6-11ea-a1c7-b499baebfeaf)");
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
"MariaDB reports :

Difficult to exploit vulnerability allows unauthenticated attacker
with network access via multiple protocols to compromise MySQL Client."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/security/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mdb-5567-rn/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mdb-10412-rn/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mdb-10322-rn/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mdb-10231-rn/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mdb-10144-rn/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mariadb-connector-c-317-release-notes/"
  );
  # https://vuxml.freebsd.org/freebsd/cb0183bb-45f6-11ea-a1c7-b499baebfeaf.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a6218ba"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb-connector-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb101-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb101-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb102-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb102-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb103-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb103-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb104-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb104-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb55-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb55-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"mariadb55-client<5.5.67")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb55-server<5.5.67")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb101-client<10.1.44")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb101-server<10.1.44")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb102-client<10.2.31")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb102-server<10.2.31")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb103-client<10.3.22")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb103-server<10.3.22")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb104-client<10.4.12")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb104-server<10.4.12")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb-connector-c<3.1.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
