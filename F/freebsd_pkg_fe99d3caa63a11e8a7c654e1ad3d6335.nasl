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
  script_id(112074);
  script_version("1.3");
  script_cvs_date("Date: 2018/11/10 11:49:47");

  script_cve_id("CVE-2018-14598", "CVE-2018-14599", "CVE-2018-14600");

  script_name(english:"FreeBSD : libX11 -- Multiple vulnerabilities (fe99d3ca-a63a-11e8-a7c6-54e1ad3d6335)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The freedesktop.org project reports :

The functions XGetFontPath, XListExtensions, and XListFonts are
vulnerable to an off-by-one override on malicious server responses.
The server replies consist of chunks consisting of a length byte
followed by actual string, which is not NUL-terminated. While parsing
the response, the length byte is overridden with '\0', thus the memory
area can be used as storage of C strings later on. To be able to
NUL-terminate the last string, the buffer is reserved with an
additional byte of space. For a boundary check, the variable chend
(end of ch) was introduced, pointing at the end of the buffer which ch
initially points to. Unfortunately there is a difference in handling
'the end of ch'. While chend points at the first byte that must not be
written to, the for-loop uses chend as the last byte that can be
written to. Therefore, an off-by-one can occur.

The length value is interpreted as signed char on many systems
(depending on default signedness of char), which can lead to an out of
boundary write up to 128 bytes in front of the allocated storage, but
limited to NUL byte(s).

If the server sends a reply in which even the first string would
overflow the transmitted bytes, list[0] (or flist[0]) will be set to
NULL and a count of 0 is returned. If the resulting list is freed with
XFreeExtensionList or XFreeFontPath later on, the first Xfree call is
turned into Xfree (NULL-1) which will most likely trigger a
segmentation fault. Casting the length value to unsigned char fixes
the problem and allows string values with up to 255 characters."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.x.org/archives/xorg-announce/2018-August/002915.html"
  );
  # https://vuxml.freebsd.org/freebsd/fe99d3ca-a63a-11e8-a7c6-54e1ad3d6335.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d7f3a46"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libX11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/23");
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

if (pkg_test(save_report:TRUE, pkg:"libX11<1.6.6,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
