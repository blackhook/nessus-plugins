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
  script_id(105090);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-3737", "CVE-2017-3738");

  script_name(english:"FreeBSD : OpenSSL -- multiple vulnerabilities (3bb451fc-db64-11e7-ac58-b499baebfeaf)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The OpenSSL project reports :

- Read/write after SSL object in error state (CVE-2017-3737) OpenSSL
1.0.2 (starting from version 1.0.2b) introduced an 'error state'
mechanism. The intent was that if a fatal error occurred during a
handshake then OpenSSL would move into the error state and would
immediately fail if you attempted to continue the handshake. This
works as designed for the explicit handshake functions
(SSL_do_handshake(), SSL_accept() and SSL_connect()), however due to a
bug it does not work correctly if SSL_read() or SSL_write() is called
directly. In that scenario, if the handshake fails then a fatal error
will be returned in the initial function call. If
SSL_read()/SSL_write() is subsequently called by the application for
the same SSL object then it will succeed and the data is passed
without being decrypted/encrypted directly from the SSL/TLS record
layer.

- rsaz_1024_mul_avx2 overflow bug on x86_64 (CVE-2017-3738) There is
an overflow bug in the AVX2 Montgomery multiplication procedure used
in exponentiation with 1024-bit moduli. No EC algorithms are affected.
Analysis suggests that attacks against RSA and DSA as a result of this
defect would be very difficult to perform and are not believed likely.
Attacks against DH1024 are considered just feasible, because most of
the work necessary to deduce information about a private key may be
performed offline. The amount of resources required for such an attack
would be significant. However, for an attack on TLS to be meaningful,
the server would have to share the DH1024 private key among multiple
clients, which is no longer an option since CVE-2016-0701."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/news/secadv/20171207.txt"
  );
  # https://vuxml.freebsd.org/freebsd/3bb451fc-db64-11e7-ac58-b499baebfeaf.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7d796f8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/08");
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

if (pkg_test(save_report:TRUE, pkg:"openssl>1.0.2<1.0.2n")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
