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
  script_id(138583);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/21");

  script_cve_id("CVE-2020-3327", "CVE-2020-3350", "CVE-2020-3481");

  script_name(english:"FreeBSD : clamav -- multiple vulnerabilities (f7a02651-c798-11ea-81d6-6805cabe6ebb)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Micah Snyder reports : CVE-2020-3350 Fixed a vulnerability a malicious
user could exploit to replace a scan target's directory with a symlink
to another path to trick clamscan, clamdscan, or clamonacc into
removing or moving a different file (such as a critical system file).
The issue would affect users that use the --move or --remove options
for clamscan, clamdscan and clamonacc. CVE-2020-3327 Fixed a
vulnerability in the ARJ archive-parsing module in ClamAV 0.102.3 that
could cause a denial-of-service (DoS) condition. Improper bounds
checking resulted in an out-of-bounds read that could cause a crash.
The previous fix for this CVE in version 0.102.3 was incomplete. This
fix correctly resolves the issue. CVE-2020-3481 Fixed a vulnerability
in the EGG archive module in ClamAV 0.102.0 - 0.102.3 that could cause
a denial-of-service (DoS) condition. Improper error handling could
cause a crash due to a NULL pointer dereference. This vulnerability is
mitigated for those using the official ClamAV signature databases
because the file type signatures in daily.cvd will not enable the EGG
archive parser in affected versions."
  );
  # https://blog.clamav.net/2020/07/clamav-01024-security-patch-released.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?788fbd01"
  );
  # https://vuxml.freebsd.org/freebsd/f7a02651-c798-11ea-81d6-6805cabe6ebb.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e3086b37"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3350");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"clamav<0.102.4,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:pkg_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
