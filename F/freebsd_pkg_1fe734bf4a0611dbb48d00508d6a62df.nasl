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
  script_id(22428);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2006-4339");
  script_xref(name:"Secunia", value:"21709");
  script_xref(name:"Secunia", value:"21982");

  script_name(english:"FreeBSD : opera -- RSA Signature Forgery (1fe734bf-4a06-11db-b48d-00508d6a62df)");
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
"Opera reports :

A specially crafted digital certificate can bypass Opera's certificate
signature verification. Forged certificates can contain any false
information the forger chooses, and Opera will still present it as
valid. Opera will not present any warning dialogs in this case, and
the security status will be the highest possible (3). This defeats the
protection against 'man in the middle', the attacks that SSL was
designed to prevent.

There is a flaw in OpenSSL's RSA signature verification that affects
digital certificates using 3 as the public exponent. Some of the
certificate issuers that are on Opera's list of trusted signers have
root certificates with 3 as the public exponent. The forged
certificate can appear to be signed by one of these."
  );
  # http://www.cdc.informatik.tu-darmstadt.de/securebrowser/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e3e5bc4"
  );
  # http://www.openssl.org/news/secadv/20060905.txt
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/news/secadv/20060905.txt"
  );
  # http://www.mozilla.org/security/announce/2006/mfsa2006-60.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-60/"
  );
  # https://vuxml.freebsd.org/freebsd/1fe734bf-4a06-11db-b48d-00508d6a62df.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06408b91"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-opera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:opera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:opera-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"opera<9.02")) flag++;
if (pkg_test(save_report:TRUE, pkg:"opera-devel<9.02")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-opera<9.02")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
