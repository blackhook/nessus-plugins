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
  script_id(105259);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-15896", "CVE-2017-15897", "CVE-2017-3738");

  script_name(english:"FreeBSD : node.js -- Data Confidentiality/Integrity Vulnerability, December 2017 (bea84a7a-e0c9-11e7-b4f3-11baa0c2df21)");
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
"Node.js reports : Data Confidentiality/Integrity Vulnerability -
CVE-2017-15896 Node.js was affected by OpenSSL vulnerability
CVE-2017-3737 in regards to the use of SSL_read() due to TLS handshake
failure. The result was that an active network attacker could send
application data to Node.js using the TLS or HTTP2 modules in a way
that bypassed TLS authentication and encryption. Uninitialized buffer
vulnerability - CVE-2017-15897 Node.js had a bug in versions 8.X and
9.X which caused buffers to not be initialized when the encoding for
the fill value did not match the encoding specified. For example,
'Buffer.alloc(0x100, 'This is not correctly encoded', 'hex');' The
buffer implementation was updated such that the buffer will be
initialized to all zeros in these cases. Also included in OpenSSL
update - CVE 2017-3738 Note that CVE 2017-3738 of OpenSSL-1.0.2
affected Node but it was low severity."
  );
  # https://nodejs.org/en/blog/vulnerability/december-2017-security-releases/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?23d8f9db"
  );
  # https://vuxml.freebsd.org/freebsd/bea84a7a-e0c9-11e7-b4f3-11baa0c2df21.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec3314c9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/15");
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

if (pkg_test(save_report:TRUE, pkg:"node4<4.8.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node6<6.12.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node8<8.9.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node<9.2.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
