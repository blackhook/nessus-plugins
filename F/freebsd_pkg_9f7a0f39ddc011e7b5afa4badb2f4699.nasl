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
  script_id(105141);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-0701", "CVE-2017-3737", "CVE-2017-3738");
  script_xref(name:"FreeBSD", value:"SA-17:12.openssl");

  script_name(english:"FreeBSD : FreeBSD -- OpenSSL multiple vulnerabilities (9f7a0f39-ddc0-11e7-b5af-a4badb2f4699)");
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
"Invoking SSL_read()/SSL_write() while in an error state causes data to
be passed without being decrypted/encrypted directly from the SSL/TLS
record layer.

In order to exploit this issue an application bug would have to be
present that resulted in a call to SSL_read()/SSL_write() being issued
after having already received a fatal error. [CVE-2017-3737]

There is an overflow bug in the x86_64 Montgomery multiplication
procedure used in exponentiation with 1024-bit moduli. This only
affects processors that support the AVX2 but not ADX extensions like
Intel Haswell (4th generation). [CVE-2017-3738] This bug only affects
FreeBSD 11.x. Impact : Applications with incorrect error handling may
inappropriately pass unencrypted data. [CVE-2017-3737]

Mishandling of carry propagation will produce incorrect output, and
make it easier for a remote attacker to obtain sensitive private-key
information. No EC algorithms are affected and analysis suggests that
attacks against RSA and DSA as a result of this defect would be very
difficult to perform and are not believed likely.

Attacks against DH1024 are considered just feasible (although very
difficult) because most of the work necessary to deduce information
about a private key may be performed offline. The amount of resources
required for such an attack would be very significant and likely only
accessible to a limited number of attackers. However, for an attack on
TLS to be meaningful, the server would have to share the DH1024
private key among multiple clients, which is no longer an option since
CVE-2016-0701. [CVE-2017-3738]"
  );
  # https://vuxml.freebsd.org/freebsd/9f7a0f39-ddc0-11e7-b5af-a4badb2f4699.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd81aece"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:FreeBSD");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info", "Settings/ParanoidReport");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


if (report_paranoia < 2) audit(AUDIT_PARANOID);

flag = 0;

if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=11.1<11.1_6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=10.4<10.4_5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=10.3<10.3_26")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
