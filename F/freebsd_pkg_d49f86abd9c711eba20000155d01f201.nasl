#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2021 Jacques Vidrine and contributors
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
include("compat.inc");

if (description)
{
  script_id(151377);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/08");

  script_cve_id("CVE-2021-29457", "CVE-2021-29458", "CVE-2021-29463", "CVE-2021-29464", "CVE-2021-29470", "CVE-2021-29473", "CVE-2021-29623", "CVE-2021-32617", "CVE-2021-3482");

  script_name(english:"FreeBSD : Exiv2 -- Multiple vulnerabilities (d49f86ab-d9c7-11eb-a200-00155d01f201)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Exiv2 teams reports :

Multiple vulnerabilities covering buffer overflows, out-of-bounds,
read of uninitialized memory and denial of serivce. The heap overflow
is triggered when Exiv2 is used to read the metadata of a crafted
image file. An attacker could potentially exploit the vulnerability to
gain code execution, if they can trick the victim into running Exiv2
on a crafted image file. The out-of-bounds read is triggered when
Exiv2 is used to write metadata into a crafted image file. An attacker
could potentially exploit the vulnerability to cause a denial of
service by crashing Exiv2, if they can trick the victim into running
Exiv2 on a crafted image file. The read of uninitialized memory is
triggered when Exiv2 is used to read the metadata of a crafted image
file. An attacker could potentially exploit the vulnerability to leak
a few bytes of stack memory, if they can trick the victim into running
Exiv2 on a crafted image file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/Exiv2/exiv2/security/advisories/GHSA-v74w-h496-cgqm"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/Exiv2/exiv2/security/advisories/GHSA-57jj-75fm-9rq5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/Exiv2/exiv2/security/advisories/GHSA-5p8g-9xf3-gfrr"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/Exiv2/exiv2/security/advisories/GHSA-jgm9-5fw5-pw9p"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/Exiv2/exiv2/security/advisories/GHSA-8949-hhfh-j7rj"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/Exiv2/exiv2/security/advisories/GHSA-7569-phvm-vwc2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/Exiv2/exiv2/security/advisories/GHSA-6253-qjwm-3q4v"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/Exiv2/exiv2/security/advisories/GHSA-w8mv-g8qq-36mj"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/Exiv2/exiv2/security/advisories/GHSA-9jp9-m3fv-2vg9"
  );
  # https://vuxml.freebsd.org/freebsd/d49f86ab-d9c7-11eb-a200-00155d01f201.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?062220b4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:exiv2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"exiv2<0.27.4,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
