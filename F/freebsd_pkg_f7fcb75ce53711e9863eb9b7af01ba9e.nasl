#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2020 Jacques Vidrine and contributors
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
  script_id(129549);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/21");

  script_cve_id("CVE-2019-15845", "CVE-2019-16201", "CVE-2019-16254", "CVE-2019-16255");

  script_name(english:"FreeBSD : ruby -- multiple vulnerabilities (f7fcb75c-e537-11e9-863e-b9b7af01ba9e)");
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
"Ruby news :

This release includes security fixes. Please check the topics below
for details.

CVE-2019-15845: A NUL injection vulnerability of File.fnmatch and
File.fnmatch?

A NUL injection vulnerability of Ruby built-in methods (File.fnmatch
and File.fnmatch?) was found. An attacker who has the control of the
path pattern parameter could exploit this vulnerability to make path
matching pass despite the intention of the program author.

CVE-2019-16201: Regular Expression Denial of Service vulnerability of
WEBrick's Digest access authentication

Regular expression denial of service vulnerability of WEBrick's Digest
authentication module was found. An attacker can exploit this
vulnerability to cause an effective denial of service against a
WEBrick service.

CVE-2019-16254: HTTP response splitting in WEBrick (Additional fix)

There is an HTTP response splitting vulnerability in WEBrick bundled
with Ruby.

CVE-2019-16255: A code injection vulnerability of Shell#[] and
Shell#test

A code injection vulnerability of Shell#[] and Shell#test in a
standard library (lib/shell.rb) was found."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.ruby-lang.org/en/news/2019/10/01/ruby-2-6-5-released/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.ruby-lang.org/en/news/2019/10/01/ruby-2-5-7-released/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.ruby-lang.org/en/news/2019/10/01/ruby-2-4-8-released/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.ruby-lang.org/en/news/2019/10/02/ruby-2-4-9-released/"
  );
  # https://www.ruby-lang.org/en/news/2019/10/01/nul-injection-file-fnmatch-cve-2019-15845/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54122b09"
  );
  # https://www.ruby-lang.org/en/news/2019/10/01/webrick-regexp-digestauth-dos-cve-2019-16201/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8f5464f"
  );
  # https://www.ruby-lang.org/en/news/2019/10/01/http-response-splitting-in-webrick-cve-2019-16254/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a9845f8"
  );
  # https://www.ruby-lang.org/en/news/2019/10/01/code-injection-shell-test-cve-2019-16255/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b50fa79"
  );
  # https://vuxml.freebsd.org/freebsd/f7fcb75c-e537-11e9-863e-b9b7af01ba9e.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3dacd927"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16255");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ruby");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"ruby>=2.4.0,1<2.4.9,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ruby>=2.5.0,1<2.5.7,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ruby>=2.6.0,1<2.6.5,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
