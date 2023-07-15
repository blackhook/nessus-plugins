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
  script_id(135729);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/24");

  script_cve_id("CVE-2020-1737");

  script_name(english:"FreeBSD : ansible - win_unzip path normalization (0899c0d3-80f2-11ea-bafd-815569f3852d)");
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
"Borja Tarraso reports :

A flaw was found in Ansible 2.7.17 and prior, 2.8.9 and prior, and
2.9.6 and prior when using the Extract-Zip function from the win_unzip
module as the extracted file(s) are not checked if they belong to the
destination folder. An attacker could take advantage of this flaw by
crafting an archive anywhere in the file system, using a path
traversal. This issue is fixed in 2.10."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ansible/ansible/issues/67795"
  );
  # https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FWDK3QUVBULS3Q3PQTGEKUQYPSNOU5M3/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c5640ce"
  );
  # https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QT27K5ZRGDPCH7GT3DRI3LO4IVDVQUB7/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e784346d"
  );
  # https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/U3IMV3XEIUXL6S4KPLYYM4TVJQ2VNEP2/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b10be199"
  );
  # https://vuxml.freebsd.org/freebsd/0899c0d3-80f2-11ea-bafd-815569f3852d.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57ce7a14"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ansible23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ansible24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ansible25");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ansible26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ansible27");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/20");
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

if (pkg_test(save_report:TRUE, pkg:"ansible<2.8.9")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ansible27<2.7.17")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ansible26<2.7.17")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ansible25<2.7.17")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ansible24<2.7.17")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ansible23<2.7.17")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
