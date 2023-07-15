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
  script_id(109050);
  script_version("1.4");
  script_cvs_date("Date: 2018/11/10 11:49:46");

  script_cve_id("CVE-2018-1000168");

  script_name(english:"FreeBSD : nghttp2 -- Denial of service due to NULL pointer dereference (1fccb25e-8451-438c-a2b9-6a021e4d7a31)");
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
"nghttp2 blog :

If ALTSVC frame is received by libnghttp2 and it is larger than it can
accept, the pointer field which points to ALTSVC frame payload is left
NULL. Later libnghttp2 attempts to access another field through the
pointer, and gets segmentation fault.

ALTSVC frame is defined by RFC 7838.

The largest frame size libnghttp2 accept is by default 16384 bytes.

Receiving ALTSVC frame is disabled by default. Application has to
enable it explicitly by calling
nghttp2_option_set_builtin_recv_extension_type(opt, NGHTTP2_ALTSVC).

Transmission of ALTSVC is always enabled, and it does not cause this
vulnerability.

ALTSVC frame is expected to be sent by server, and received by client
as defined in RFC 7838.

Client and server are both affected by this vulnerability if the
reception of ALTSVC frame is enabled. As written earlier, it is
useless to enable reception of ALTSVC frame on server side. So, server
is generally safe unless application accidentally enabled the
reception of ALTSVC frame."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://nghttp2.org/blog/2018/04/12/nghttp2-v1-31-1/"
  );
  # https://vuxml.freebsd.org/freebsd/1fccb25e-8451-438c-a2b9-6a021e4d7a31.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c63c4178"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libnghttp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:nghttp2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/16");
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

if (pkg_test(save_report:TRUE, pkg:"libnghttp2>=1.10.0<1.31.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"nghttp2>=1.10.0<1.31.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
