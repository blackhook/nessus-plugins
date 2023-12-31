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
  script_id(85859);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2015-6834", "CVE-2015-6835", "CVE-2015-6836", "CVE-2015-6837", "CVE-2015-6838");

  script_name(english:"FreeBSD : php -- multiple vulnerabilities (3d675519-5654-11e5-9ad8-14dae9d210b8)");
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
"PHP reports :

- Core :

- Fixed bug #70172 (Use After Free Vulnerability in unserialize()).

- Fixed bug #70219 (Use after free vulnerability in session
deserializer).

- EXIF :

- Fixed bug #70385 (Buffer over-read in exif_read_data with TIFF IFD
tag byte value of 32 bytes).

- hash :

- Fixed bug #70312 (HAVAL gives wrong hashes in specific cases).

- PCRE :

- Fixed bug #70345 (Multiple vulnerabilities related to PCRE
functions).

- SOAP :

- Fixed bug #70388 (SOAP serialize_function_call() type confusion /
RCE).

- SPL :

- Fixed bug #70365 (Use-after-free vulnerability in unserialize() with
SplObjectStorage).

- Fixed bug #70366 (Use-after-free vulnerability in unserialize() with
SplDoublyLinkedList).

- XSLT :

- Fixed bug #69782 (NULL pointer dereference).

- ZIP :

- Fixed bug #70350 (ZipArchive::extractTo allows for directory
traversal when creating directories)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.4.45"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.5.29"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.6.13"
  );
  # https://vuxml.freebsd.org/freebsd/3d675519-5654-11e5-9ad8-14dae9d210b8.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27403633"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-xsl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"php5<5.4.45")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-soap<5.4.45")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-xsl<5.4.45")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55<5.5.29")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-soap<5.5.29")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-xsl<5.5.29")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56<5.6.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-soap<5.6.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-xsl<5.6.13")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
