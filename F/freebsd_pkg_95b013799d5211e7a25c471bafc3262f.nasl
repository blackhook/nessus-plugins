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
  script_id(103345);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-0898", "CVE-2017-10784", "CVE-2017-14033", "CVE-2017-14064");

  script_name(english:"FreeBSD : ruby -- multiple vulnerabilities (95b01379-9d52-11e7-a25c-471bafc3262f)");
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
"Ruby blog :

CVE-2017-0898: Buffer underrun vulnerability in Kernel.sprintf

If a malicious format string which contains a precious specifier (*)
is passed and a huge minus value is also passed to the specifier,
buffer underrun may be caused. In such situation, the result may
contains heap, or the Ruby interpreter may crash.

CVE-2017-10784: Escape sequence injection vulnerability in the Basic
authentication of WEBrick

When using the Basic authentication of WEBrick, clients can pass an
arbitrary string as the user name. WEBrick outputs the passed user
name intact to its log, then an attacker can inject malicious escape
sequences to the log and dangerous control characters may be executed
on a victim's terminal emulator.

This vulnerability is similar to a vulnerability already fixed, but it
had not been fixed in the Basic authentication.

CVE-2017-14033: Buffer underrun vulnerability in OpenSSL ASN1 decode

If a malicious string is passed to the decode method of OpenSSL::ASN1,
buffer underrun may be caused and the Ruby interpreter may crash.

CVE-2017-14064: Heap exposure vulnerability in generating JSON

The generate method of JSON module optionally accepts an instance of
JSON::Ext::Generator::State class. If a malicious instance is passed,
the result may include contents of heap."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.ruby-lang.org/en/security/"
  );
  # https://www.ruby-lang.org/en/news/2017/09/14/sprintf-buffer-underrun-cve-2017-0898/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0909107e"
  );
  # https://www.ruby-lang.org/en/news/2017/09/14/webrick-basic-auth-escape-sequence-injection-cve-2017-10784/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90a3a566"
  );
  # https://www.ruby-lang.org/en/news/2017/09/14/openssl-asn1-buffer-underrun-cve-2017-14033/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5429c6d6"
  );
  # https://www.ruby-lang.org/en/news/2017/09/14/json-heap-exposure-cve-2017-14064/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d043841"
  );
  # https://vuxml.freebsd.org/freebsd/95b01379-9d52-11e7-a25c-471bafc3262f.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fcd11fe5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ruby");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/20");
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

if (pkg_test(save_report:TRUE, pkg:"ruby>=2.2.0<2.2.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ruby>=2.3.0<2.3.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ruby>=2.4.0<2.4.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
