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
  script_id(109749);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/05 23:25:06");

  script_cve_id("CVE-2018-10536", "CVE-2018-10537", "CVE-2018-10538", "CVE-2018-10539", "CVE-2018-10540", "CVE-2018-6767", "CVE-2018-7253", "CVE-2018-7254");
  script_xref(name:"DSA", value:"4125");
  script_xref(name:"DSA", value:"4197");

  script_name(english:"FreeBSD : wavpack -- multiple vulnerabilities (50210bc1-54ef-11e8-95d9-9c5c8e75236a)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sebastian Ramacher reports :

A stack-based buffer over-read in the ParseRiffHeaderConfig function
of cli/riff.c file of WavPack 5.1.0 allows a remote attacker to cause
a denial-of-service attack or possibly have unspecified other impact
via a maliciously crafted RF64 file.

The ParseDsdiffHeaderConfig function of the cli/dsdiff.c file of
WavPack 5.1.0 allows a remote attacker to cause a denial-of-service
(heap-based buffer over-read) or possibly overwrite the heap via a
maliciously crafted DSDIFF file.

The ParseCaffHeaderConfig function of the cli/caff.c file of WavPack
5.1.0 allows a remote attacker to cause a denial-of-service (global
buffer over-read), or possibly trigger a buffer overflow or incorrect
memory allocation, via a maliciously crafted CAF file.

Thuan Pham reports :

An issue was discovered in WavPack 5.1.0 and earlier. The WAV parser
component contains a vulnerability that allows writing to memory
because ParseRiffHeaderConfig in riff.c does not reject multiple
format chunks.

An issue was discovered in WavPack 5.1.0 and earlier. The W64 parser
component contains a vulnerability that allows writing to memory
because ParseWave64HeaderConfig in wave64.c does not reject multiple
format chunks.

An issue was discovered in WavPack 5.1.0 and earlier for WAV input.
Out-of-bounds writes can occur because ParseRiffHeaderConfig in riff.c
does not validate the sizes of unknown chunks before attempting memory
allocation, related to a lack of integer-overflow protection within a
bytes_to_copy calculation and subsequent malloc call, leading to
insufficient memory allocation.

An issue was discovered in WavPack 5.1.0 and earlier for DSDiff input.
Out-of-bounds writes can occur because ParseDsdiffHeaderConfig in
dsdiff.c does not validate the sizes of unknown chunks before
attempting memory allocation, related to a lack of integer-overflow
protection within a bytes_to_copy calculation and subsequent malloc
call, leading to insufficient memory allocation.

An issue was discovered in WavPack 5.1.0 and earlier for W64 input.
Out-of-bounds writes can occur because ParseWave64HeaderConfig in
wave64.c does not validate the sizes of unknown chunks before
attempting memory allocation, related to a lack of integer-overflow
protection within a bytes_to_copy calculation and subsequent malloc
call, leading to insufficient memory allocation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=228141"
  );
  # https://vuxml.freebsd.org/freebsd/50210bc1-54ef-11e8-95d9-9c5c8e75236a.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d994b37c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wavpack");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"wavpack<5.1.0_1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
