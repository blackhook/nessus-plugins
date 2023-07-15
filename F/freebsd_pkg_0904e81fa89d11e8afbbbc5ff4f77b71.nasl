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
  script_id(112128);
  script_version("1.3");
  script_cvs_date("Date: 2018/11/10 11:49:46");

  script_cve_id("CVE-2018-0732", "CVE-2018-12115", "CVE-2018-7166");

  script_name(english:"FreeBSD : node.js -- multiple vulnerabilities (0904e81f-a89d-11e8-afbb-bc5ff4f77b71)");
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
"Node.js reports : OpenSSL: Client DoS due to large DH parameter This
fixes a potential denial of service (DoS) attack against client
connections by a malicious server. During a TLS communication
handshake, where both client and server agree to use a cipher-suite
using DH or DHE (Diffie-Hellman, in both ephemeral and non-ephemeral
modes), a malicious server can send a very large prime value to the
client. Because this has been unbounded in OpenSSL, the client can be
forced to spend an unreasonably long period of time to generate a key,
potentially causing a denial of service. OpenSSL: ECDSA key extraction
via local side-channel Attackers with access to observe cache-timing
may be able to extract DSA or ECDSA private keys by causing the victim
to create several signatures and watching responses. This flaw does
not have a CVE due to OpenSSL policy to not assign itself CVEs for
local-only vulnerabilities that are more academic than practical. This
vulnerability was discovered by Keegan Ryan at NCC Group and impacts
many cryptographic libraries including OpenSSL. Unintentional exposure
of uninitialized memory Only Node.js 10 is impacted by this flaw.

Node.js TSC member Nikita Skovoroda discovered an argument processing
flaw that causes Buffer.alloc() to return uninitialized memory. This
method is intended to be safe and only return initialized, or cleared,
memory. The third argument specifying encoding can be passed as a
number, this is misinterpreted by Buffer's internal 'fill' method as
the start to a fill operation. This flaw may be abused where
Buffer.alloc() arguments are derived from user input to return
uncleared memory blocks that may contain sensitive information. Out of
bounds (OOB) write Node.js TSC member Nikita Skovoroda discovered an
OOB write in Buffer that can be used to write to memory outside of a
Buffer's memory space. This can corrupt unrelated Buffer objects or
cause the Node.js process to crash.

When used with UCS-2 encoding (recognized by Node.js under the names
'ucs2', 'ucs-2', 'utf16le' and 'utf-16le'), Buffer#write() can be
abused to write outside of the bounds of a single Buffer. Writes that
start from the second-to-last position of a buffer cause a
miscalculation of the maximum length of the input bytes to be written."
  );
  # https://nodejs.org/en/blog/vulnerability/august-2018-security-releases/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f738f917"
  );
  # https://vuxml.freebsd.org/freebsd/0904e81f-a89d-11e8-afbb-bc5ff4f77b71.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd119c51"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/28");
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

if (pkg_test(save_report:TRUE, pkg:"node<10.9.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node8<8.11.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node6<6.14.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
