#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
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

include('compat.inc');

if (description)
{
  script_id(174287);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/30");

  script_cve_id("CVE-2023-28879");
  script_xref(name:"IAVB", value:"2023-B-0023-S");

  script_name(english:"FreeBSD : ghostscript -- exploitable buffer overflow in (T)BCP in PS interpreter (25872b25-da2d-11ed-b715-a1e76793953b)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the 25872b25-da2d-11ed-b715-a1e76793953b advisory.

  - In Artifex Ghostscript through 10.01.0, there is a buffer overflow leading to potential corruption of data
    internal to the PostScript interpreter, in base/sbcp.c. This affects BCPEncode, BCPDecode, TBCPEncode, and
    TBCPDecode. If the write buffer is filled to one byte less than full, and one then tries to write an
    escaped character, two bytes are written. (CVE-2023-28879)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://artifex.com/news/critical-security-vulnerability-fixed-in-ghostscript
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?042571c8");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2023-28879");
  # https://vuxml.freebsd.org/freebsd/25872b25-da2d-11ed-b715-a1e76793953b.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?825beb40");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28879");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ghostscript7-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ghostscript7-commfont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ghostscript7-jpnfont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ghostscript7-korfont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ghostscript7-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ghostscript8-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ghostscript8-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ghostscript9-agpl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ghostscript9-agpl-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("freebsd_package.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


var flag = 0;

var packages = [
    'ghostscript7-base<10.01.0',
    'ghostscript7-commfont<10.01.0',
    'ghostscript7-jpnfont<10.01.0',
    'ghostscript7-korfont<10.01.0',
    'ghostscript7-x11<10.01.0',
    'ghostscript8-base<10.01.0',
    'ghostscript8-x11<10.01.0',
    'ghostscript9-agpl-base<10.01.0',
    'ghostscript9-agpl-x11<10.01.0',
    'ghostscript<10.01.0'
];

foreach var package( packages ) {
    if (pkg_test(save_report:TRUE, pkg: package)) flag++;
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : pkg_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
