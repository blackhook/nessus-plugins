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
  script_id(110969);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/21");

  script_cve_id("CVE-2017-5974", "CVE-2017-5975", "CVE-2017-5976", "CVE-2017-5977", "CVE-2017-5978", "CVE-2017-5979", "CVE-2017-5980", "CVE-2017-5981", "CVE-2018-6381", "CVE-2018-6484", "CVE-2018-6540", "CVE-2018-6541", "CVE-2018-6542", "CVE-2018-6869", "CVE-2018-7725", "CVE-2018-7726", "CVE-2018-7727");

  script_name(english:"FreeBSD : zziplib - multiple vulnerabilities (7764b219-8148-11e8-aa4d-000e0cd7b374)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"NIST reports (by search in the range 2017/01/01 - 2018/07/06) :

17 security fixes in this release :

- Heap-based buffer overflow in the __zzip_get32 function in fetch.c.

- Heap-based buffer overflow in the __zzip_get64 function in fetch.c.

- Heap-based buffer overflow in the zzip_mem_entry_extra_block
function in memdisk.c.

- The zzip_mem_entry_new function in memdisk.c allows remote attackers
to cause a denial of service (out-of-bounds read and crash) via a
crafted ZIP file.

- The prescan_entry function in fseeko.c allows remote attackers to
cause a denial of service (NULL pointer dereference and crash) via
crafted ZIP file.

- The zzip_mem_entry_new function in memdisk.c cause a NULL pointer
dereference and crash via a crafted ZIP file.

- seeko.c cause a denial of service (assertion failure and crash) via
a crafted ZIP file.

- A segmentation fault caused by invalid memory access in the
zzip_disk_fread function because the size variable is not validated
against the amount of file->stored data.

- A memory alignment error and bus error in the
__zzip_fetch_disk_trailer function of zzip/zip.c.

- A bus error caused by loading of a misaligned address in the
zzip_disk_findfirst function.

- An uncontrolled memory allocation and a crash in the
__zzip_parse_root_directory function.

- An invalid memory address dereference was discovered in
zzip_disk_fread in mmapped.c.

- A memory leak triggered in the function zzip_mem_disk_new in
memdisk.c."
  );
  # https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&query=zziplib&search_type=all&pub_start_date=01%2F01%2F2017&pub_end_date=07%2F06%2F2018
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26fb49e6"
  );
  # https://vuxml.freebsd.org/freebsd/7764b219-8148-11e8-aa4d-000e0cd7b374.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eae19ef5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zziplib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"zziplib<0.13.68")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
