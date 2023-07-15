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
include('compat.inc');

if (description)
{
  script_id(154658);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/29");

  script_cve_id("CVE-2021-39226");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/15");

  script_name(english:"FreeBSD : Grafana -- Snapshot authentication bypass (757ee63b-269a-11ec-a616-6c3be5272acd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related
updates.");
  script_set_attribute(attribute:"description", value:
"Grafana Labs reports :

Unauthenticated and authenticated users are able to view the snapshot
with the lowest database key by accessing the literal paths :

- /dashboard/snapshot/:key, or

- /api/snapshots/:key

If the snapshot 'public_mode' configuration setting is set to true (vs
default of false), unauthenticated users are able to delete the
snapshot with the lowest database key by accessing the literal path :

- /api/snapshots-delete/:deleteKey

Regardless of the snapshot 'public_mode' setting, authenticated users
are able to delete the snapshot with the lowest database key by
accessing the literal paths :

- /api/snapshots/:key, or

- /api/snapshots-delete/:deleteKey

The combination of deletion and viewing enables a complete walk
through all snapshot data while resulting in complete snapshot data
loss.");
  # https://grafana.com/blog/2021/10/05/grafana-7.5.11-and-8.1.6-released-with-critical-security-fix/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?caaa986c");
  # https://vuxml.freebsd.org/freebsd/757ee63b-269a-11ec-a616-6c3be5272acd.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da1286a2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39226");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:grafana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:grafana6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:grafana7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:grafana8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (pkg_test(save_report:TRUE, pkg:"grafana8>=8.0.0<8.1.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"grafana8>=2.0.1<7.5.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"grafana7>=8.0.0<8.1.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"grafana7>=2.0.1<7.5.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"grafana6>=8.0.0<8.1.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"grafana6>=2.0.1<7.5.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"grafana>=8.0.0<8.1.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"grafana>=2.0.1<7.5.11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
