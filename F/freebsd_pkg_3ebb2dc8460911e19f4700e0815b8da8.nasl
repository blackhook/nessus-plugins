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
  script_id(57646);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2012-0041", "CVE-2012-0066", "CVE-2012-0067", "CVE-2012-0068");

  script_name(english:"FreeBSD : Wireshark -- Multiple vulnerabilities (3ebb2dc8-4609-11e1-9f47-00e0815b8da8)");
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
"Wireshark reports :

Laurent Butti discovered that Wireshark failed to properly check
record sizes for many packet capture file formats

Wireshark could dereference a NULL pointer and crash.

The RLC dissector could overflow a buffer."
  );
  # http://www.wireshark.org/security/wnpa-sec-2012-01.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2012-01.html"
  );
  # http://www.wireshark.org/security/wnpa-sec-2012-02.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2012-02.html"
  );
  # http://www.wireshark.org/security/wnpa-sec-2012-03.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2012-03.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6391"
  );
  # https://vuxml.freebsd.org/freebsd/3ebb2dc8-4609-11e1-9f47-00e0815b8da8.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e0ceafae"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tshark-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wireshark-lite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"wireshark>=1.4<1.4.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"wireshark>=1.6.0<1.6.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"wireshark-lite>=1.4<1.4.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"wireshark-lite>=1.6.0<1.6.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tshark>=1.4<1.4.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tshark>=1.6.0<1.6.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tshark-lite>=1.4<1.4.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tshark-lite>=1.6.0<1.6.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
