//! PDF renderer.
//!
//! printpdf is used with its HTML/fontconfig features off, so the binary does
//! not need a system font or a C library. DejaVu Sans is embedded because the
//! standard PDF fonts do not contain ✔ ● ▲ ■ ✖ ○. Color is decoration: every
//! badge already carries the letter, the word, and the shape as text.

use anyhow::{bail, Result};
use printpdf::{
    Color, Line, LinePoint, Mm, Op, PaintMode, ParsedFont, PdfDocument, PdfFontHandle, PdfPage,
    PdfSaveOptions, Point, Pt, RawImage, Rect, Rgb, TextItem, XObjectId, XObjectTransform,
};

use crate::report::model::ReportModel;
use crate::report::severity::{Grade, Severity, SeverityCounts};

const SANS: &[u8] = include_bytes!("../../assets/fonts/DejaVuSans.ttf");
const SANS_BOLD: &[u8] = include_bytes!("../../assets/fonts/DejaVuSans-Bold.ttf");

const TEXT: (f32, f32, f32) = (0.12, 0.12, 0.12);
const MUTED: (f32, f32, f32) = (0.33, 0.33, 0.33);
const RULE: (f32, f32, f32) = (0.62, 0.62, 0.62);
const BAND: (f32, f32, f32) = (0.93, 0.93, 0.93);

struct Writer<'a> {
    regular: &'a ParsedFont,
    bold: &'a ParsedFont,
    regular_id: printpdf::FontId,
    bold_id: printpdf::FontId,
    logo: Option<(XObjectId, f32, f32)>,
    accent: (f32, f32, f32),
    report_id: String,
    page_w: f32,
    page_h: f32,
    left: f32,
    right: f32,
    content_top: f32,
    content_bottom: f32,
    y: f32,
    ops: Vec<Op>,
    pages: Vec<Vec<Op>>,
}

pub fn render(model: &ReportModel) -> Result<Vec<u8>> {
    let mut font_warnings = Vec::new();
    let regular = ParsedFont::from_bytes(SANS, 0, &mut font_warnings).ok_or_else(|| {
        anyhow::anyhow!("Failed to parse embedded DejaVu Sans: {font_warnings:?}")
    })?;
    let bold = ParsedFont::from_bytes(SANS_BOLD, 0, &mut font_warnings).ok_or_else(|| {
        anyhow::anyhow!("Failed to parse embedded DejaVu Sans Bold: {font_warnings:?}")
    })?;

    let title = format!(
        "External Exposure Check — {}",
        blank(&model.config.client_legal_name, "client")
    );
    let mut doc = PdfDocument::new(&title);
    let regular_id = doc.add_font(&regular);
    let bold_id = doc.add_font(&bold);
    let logo = match &model.config.logo {
        Some(bytes) => {
            let image = RawImage::decode_from_bytes(bytes, &mut Vec::new())
                .map_err(|err| anyhow::anyhow!("Could not decode the logo image: {err}"))?;
            let id = doc.add_image(&image);
            Some((id, image.width as f32, image.height as f32))
        }
        None => None,
    };

    let page_w = mm(210.0);
    let page_h = mm(297.0);
    let left = mm(16.0);
    let mut writer = Writer {
        regular: &regular,
        bold: &bold,
        regular_id,
        bold_id,
        logo,
        accent: model.config.accent,
        report_id: model.config.report_id.clone(),
        page_w,
        page_h,
        left,
        right: page_w - mm(16.0),
        content_top: page_h - mm(14.0),
        content_bottom: mm(16.0),
        y: 0.0,
        ops: Vec::new(),
        pages: Vec::new(),
    };
    writer.y = writer.content_top;
    writer.write_report(model);
    let pages = writer.finish();
    if pages.is_empty() {
        bail!("Report renderer produced no pages");
    }
    let pdf_pages = pages
        .into_iter()
        .map(|ops| PdfPage::new(Mm(210.0), Mm(297.0), ops))
        .collect();
    let mut warnings = Vec::new();
    let bytes = doc.with_pages(pdf_pages).save(
        &PdfSaveOptions {
            // Subsetting has dropped glyphs in older printpdf builds. Embed the
            // face so the severity shapes survive.
            subset_fonts: false,
            ..PdfSaveOptions::default()
        },
        &mut warnings,
    );
    if !bytes.starts_with(b"%PDF") {
        bail!("PDF library did not produce a PDF ({warnings:?})");
    }
    Ok(bytes)
}

impl<'a> Writer<'a> {
    fn write_report(&mut self, model: &ReportModel) {
        self.cover(model);
        self.page_break();
        self.heading("Scope and authorization");
        self.scope_box(model);
        self.heading("Executive summary");
        self.summary(model);
        self.heading("Risk grade");
        self.grade_table(model);
        self.heading("Fix-first list");
        self.fix_first(model);
        self.heading("Findings");
        self.findings(model);
        self.heading("What we checked and what we didn't");
        self.methodology(model);
        self.heading("Next steps");
        self.next_steps(model);
        self.heading("Appendix A — open ports");
        self.appendix_a(model);
        self.heading("Appendix B — glossary");
        self.glossary();
        if model.config.insurance_appendix {
            self.page_break();
            self.heading("Appendix C — insurance evidence letter");
            self.insurance_letter(model);
        }
    }

    fn cover(&mut self, model: &ReportModel) {
        self.paragraph("CONFIDENTIAL", 9.0, true, MUTED);
        self.gap(2.0);
        self.paragraph("Weeks IT Solutions", 16.0, true, TEXT);
        self.paragraph("nullps1 | systems builder", 10.0, false, MUTED);
        self.paragraph("weeksitsolutions.com", 10.0, false, MUTED);
        self.gap(10.0);
        self.paragraph("External Exposure Check", 20.0, true, TEXT);
        self.gap(4.0);
        self.paragraph(
            &blank(&model.config.client_legal_name, "Client name not provided"),
            13.0,
            true,
            TEXT,
        );
        self.gap(8.0);
        self.badge(&model.grade);
        self.gap(4.0);
        self.paragraph(&model.summary_sentence, 11.0, false, TEXT);
        self.gap(6.0);
        self.paragraph("Top 3 items", 12.0, true, TEXT);
        if model.fix_first.is_empty() {
            self.paragraph(
                "Nothing above informational. No items to fix first.",
                10.5,
                false,
                TEXT,
            );
        } else {
            for (index, action) in model.top_actions.iter().take(3).enumerate() {
                self.paragraph(&format!("{}. {action}", index + 1), 10.5, false, TEXT);
            }
        }
    }

    fn scope_box(&mut self, model: &ReportModel) {
        let signer = match (
            model.config.signer_name.trim().is_empty(),
            model.config.signer_title.trim().is_empty(),
        ) {
            (false, false) => format!(
                "{}, {}",
                model.config.signer_name, model.config.signer_title
            ),
            (false, true) => model.config.signer_name.clone(),
            (true, false) => model.config.signer_title.clone(),
            (true, true) => "not provided".to_string(),
        };
        self.field(
            "Client legal name",
            &blank(&model.config.client_legal_name, "not provided"),
        );
        self.field(
            "Client contact",
            &blank(&model.config.client_contact, "not provided"),
        );
        self.field("Authorization reference", &model.config.auth_ref);
        self.field("Signer", &signer);
        self.field(
            "Signed date",
            &blank(&model.config.signed_date, "not provided"),
        );
        self.field(
            "Scope",
            &blank(&model.config.scope, "Client-owned public assets only."),
        );
        self.field("Assets", &model.summary.scope_assets);
        self.field("Scan record target", &model.summary.scan_target);
        self.field(
            "Scan window",
            &format!(
                "{}  to  {} ({})",
                model.summary.window_start, model.summary.window_end, model.summary.timezone_label
            ),
        );
        self.field("nullscan version", &model.summary.nullscan_version);
        self.field("CVE database date", &model.summary.vuln_db_date);
        self.field(
            "Report ID and version",
            &format!(
                "{} / {}",
                model.config.report_id, model.config.report_version
            ),
        );
        self.field("Prepared by", &model.config.prepared_by);
        self.field("Delivery date", &model.config.delivery_date);
        self.gap(4.0);
        self.note("Times are shown in America/Denver.");
    }

    fn summary(&mut self, model: &ReportModel) {
        self.paragraph(&count_line(&model.counts), 11.0, false, TEXT);
        self.gap(3.0);
        self.paragraph(
            &format!(
                "Ports in the scan record: {} scanned, {} open, {} closed or filtered. Duration: {}.",
                model.summary.total_ports,
                model.summary.open_ports,
                model.summary.closed_ports,
                model.summary.duration
            ),
            10.0,
            false,
            TEXT,
        );
    }

    fn grade_table(&mut self, model: &ReportModel) {
        self.paragraph(
            "The grade uses counts of findings. Informational items do not lower the grade. Low items do not lower it below A.",
            10.0,
            false,
            TEXT,
        );
        self.gap(3.0);
        let rows = grade_rows(model.grade.letter);
        self.table(
            &[
                ("Grade", 0.12),
                ("Label", 0.24),
                ("Shape", 0.12),
                ("Rule", 0.36),
                ("This client", 0.16),
            ],
            &rows,
            8.5,
        );
        self.gap(4.0);
        self.paragraph(
            "Severity tags, printed as text: [CRITICAL ✖]  [HIGH ■]  [MEDIUM ▲]  [LOW ●]  [INFO ○]",
            9.0,
            false,
            TEXT,
        );
        self.note("A tag is the word plus the shape. Do not rely on color.");
    }

    fn fix_first(&mut self, model: &ReportModel) {
        if model.fix_first.is_empty() {
            self.paragraph(
                "No finding rose above informational. Nothing is on the fix-first list.",
                10.0,
                false,
                TEXT,
            );
            return;
        }
        self.paragraph(
            "Sorted by severity, highest first. Informational items are in the appendix only.",
            10.0,
            false,
            TEXT,
        );
        self.gap(3.0);
        let rows = model
            .fix_first
            .iter()
            .enumerate()
            .map(|(index, row)| {
                vec![
                    (index + 1).to_string(),
                    row.name.clone(),
                    row.where_label.clone(),
                    row.severity.tag(),
                    row.effort.clone(),
                    row.who.clone(),
                ]
            })
            .collect::<Vec<_>>();
        self.table(
            &[
                ("#", 0.06),
                ("Finding", 0.26),
                ("Where", 0.24),
                ("Severity", 0.18),
                ("Effort", 0.13),
                ("Who", 0.13),
            ],
            &rows,
            8.0,
        );
    }

    fn findings(&mut self, model: &ReportModel) {
        if model.findings.is_empty() {
            self.paragraph("No finding rose above informational.", 10.0, false, TEXT);
            return;
        }
        for finding in &model.findings {
            self.ensure(70.0);
            self.paragraph(&finding.title, 12.0, true, TEXT);
            self.paragraph(
                &format!(
                    "{}  ·  Where: {}  ·  Detected: {}",
                    finding.severity.tag(),
                    finding.where_label,
                    finding.detected
                ),
                9.0,
                false,
                MUTED,
            );
            self.gap(2.0);
            self.paragraph(&format!("What it is: {}", finding.what), 10.0, false, TEXT);
            self.paragraph(
                &format!("Why it matters: {}", finding.why),
                10.0,
                false,
                TEXT,
            );
            self.paragraph("What to do:", 10.0, true, TEXT);
            for (index, step) in finding.steps.iter().enumerate() {
                self.paragraph(&format!("{}. {step}", index + 1), 10.0, false, TEXT);
            }
            self.paragraph(
                &format!("Who: {}. Effort: {}.", finding.who, finding.effort),
                10.0,
                false,
                TEXT,
            );
            self.gap(1.0);
            self.paragraph("Technical detail", 8.5, true, MUTED);
            for line in &finding.technical {
                self.paragraph(line, 8.0, false, MUTED);
            }
            self.gap(6.0);
        }
    }

    fn methodology(&mut self, model: &ReportModel) {
        let checked = [
            format!(
                "We tried TCP connections to the authorized addresses ({}) and recorded which ports answered. The scan record says the target was {}.",
                model.summary.scope_assets, model.summary.scan_target
            ),
            "When the scan grabbed banners, we recorded the text the service sent and the name nullscan gave that service.".to_string(),
            "When the scan checked the vulnerability database, CVE ids were inferred from that banner text. A match means the service may be affected and needs confirming. We did not prove the issue is present, and we did not try to exploit anything.".to_string(),
            format!(
                "Scanner version: {}. CVE database date: {}.",
                model.summary.nullscan_version, model.summary.vuln_db_date
            ),
        ];
        self.paragraph("What we checked", 11.0, true, TEXT);
        for line in &checked {
            self.paragraph(&format!("• {line}"), 10.0, false, TEXT);
        }
        self.gap(3.0);
        self.paragraph("What we didn't", 11.0, true, TEXT);
        for line in [
            "This is an external exposure check. It is not a penetration test, a compliance certification, or a guarantee of security.",
            "We did not guess passwords, log in, or run exploits.",
            "nullscan looks at TCP. UDP, internal-only ports, and hosts that drop our packets are outside this check. A closed result can mean filtered rather than absent.",
            "End-of-life software is flagged only when the banner matches a short editable list in the scanner. A service can be out of date without that list saying so.",
            "\"Known mail host\" means the address was listed in the report config. The scanner does not know who a company's mail provider is. It also does not log into mail servers, so it cannot tell whether SMTP login on ports 25 and 587 is encrypted. Plain POP (110) and IMAP (143) are treated as unencrypted mail login.",
            "\"SSH world-open\" means port 22, or a service named SSH, accepted a connection during this external scan. We cannot see a firewall that we did not pass.",
        ] {
            self.paragraph(&format!("• {line}"), 10.0, false, TEXT);
        }
        self.gap(3.0);
        self.paragraph("Disclaimers", 11.0, true, TEXT);
        for line in &model.disclaimers {
            self.paragraph(&format!("• {line}"), 9.0, false, TEXT);
        }
    }

    fn next_steps(&mut self, model: &ReportModel) {
        self.offer_line("Rescan", &model.config.rescan_offer);
        self.offer_line("Monitoring", &model.config.monitoring_offer);
        self.paragraph(
            &format!(
                "Help fixing: {}, {}, {}. weeksitsolutions.com",
                blank(&model.config.contact_name, "Noah Weeks"),
                blank(&model.config.contact_email, "noah@weeksitsolutions.com"),
                blank(&model.config.contact_phone, "phone not provided")
            ),
            10.5,
            false,
            TEXT,
        );
        self.paragraph(
            "Do the fix-first list, then scan the same authorized addresses again so the grade can be compared.",
            10.5,
            false,
            TEXT,
        );
    }

    fn appendix_a(&mut self, model: &ReportModel) {
        self.paragraph(
            "Every open port from the scan export, including informational items. Protocol is TCP because that is what nullscan connects to. CVE rows use the wording \"may be affected, needs confirming\".",
            9.0,
            false,
            TEXT,
        );
        self.gap(3.0);
        if model.appendix.is_empty() {
            self.paragraph("No open ports were in the scan export.", 10.0, false, TEXT);
            return;
        }
        let rows = model
            .appendix
            .iter()
            .map(|row| {
                vec![
                    row.host.clone(),
                    row.port.to_string(),
                    row.protocol.to_string(),
                    row.service.clone(),
                    row.banner.clone(),
                    if row.cves.is_empty() {
                        "none matched".to_string()
                    } else {
                        row.cves.join(" | ")
                    },
                ]
            })
            .collect::<Vec<_>>();
        self.table(
            &[
                ("Host", 0.20),
                ("Port", 0.08),
                ("Proto", 0.08),
                ("Service", 0.14),
                ("Banner", 0.22),
                ("CVEs", 0.28),
            ],
            &rows,
            7.0,
        );
    }

    fn glossary(&mut self) {
        for (term, meaning) in GLOSSARY {
            self.paragraph(&format!("{term} — {meaning}"), 10.0, false, TEXT);
            self.gap(1.5);
        }
    }

    fn insurance_letter(&mut self, model: &ReportModel) {
        self.paragraph("Weeks IT Solutions", 12.0, true, TEXT);
        self.paragraph("nullps1 | systems builder", 9.0, false, MUTED);
        self.paragraph(&model.config.delivery_date, 10.0, false, TEXT);
        self.gap(6.0);
        self.paragraph(
            &format!(
                "Re: External exposure check for {}",
                blank(&model.config.client_legal_name, "the client")
            ),
            11.0,
            true,
            TEXT,
        );
        self.gap(4.0);
        self.paragraph(
            &format!(
                "To whom it may concern: Weeks IT Solutions performed an external exposure check of the assets listed below for {}. The work was done under written authorization {} signed {}.",
                blank(&model.config.client_legal_name, "the client"),
                model.config.auth_ref,
                blank(&model.config.signed_date, "an unrecorded date")
            ),
            10.5,
            false,
            TEXT,
        );
        self.gap(3.0);
        self.paragraph(
            &format!(
                "Scan window ({}): {} to {}. nullscan {}, CVE database date {}.",
                model.summary.timezone_label,
                model.summary.window_start,
                model.summary.window_end,
                model.summary.nullscan_version,
                model.summary.vuln_db_date
            ),
            10.5,
            false,
            TEXT,
        );
        self.paragraph(
            &format!("Scope: {}", model.summary.scope_assets),
            10.5,
            false,
            TEXT,
        );
        self.gap(3.0);
        self.paragraph(
            &format!(
                "Overall grade: {}. {}",
                model.grade.badge(),
                model.grade.meaning
            ),
            10.5,
            false,
            TEXT,
        );
        self.paragraph(&count_line(&model.counts), 10.5, false, TEXT);
        self.gap(3.0);
        self.paragraph(
            "This letter records the scope, the date, and the grade of that check. It is not a penetration test, a compliance certification, or a guarantee of security. No exploitation was attempted. Possible issues were inferred from service banners and may be wrong or incomplete.",
            10.5,
            false,
            TEXT,
        );
        self.gap(3.0);
        self.paragraph("Not legal advice.", 10.5, true, TEXT);
        self.signature_block(model);
    }

    fn signature_block(&mut self, model: &ReportModel) {
        self.gap(10.0);
        self.paragraph("Authorized signature", 11.0, true, TEXT);
        self.gap(18.0);
        self.signature_rule();
        self.paragraph(
            &blank(&model.config.prepared_by, "Preparer"),
            10.5,
            false,
            TEXT,
        );
        self.paragraph("Weeks IT Solutions", 10.0, false, MUTED);
        self.paragraph("weeksitsolutions.com", 10.0, false, MUTED);
        self.paragraph(
            &format!(
                "Date: {}",
                blank(&model.config.delivery_date, "not recorded")
            ),
            10.5,
            false,
            TEXT,
        );
    }

    fn signature_rule(&mut self) {
        self.ensure(8.0);
        let y = self.y;
        let end = (self.left + 220.0).min(self.right);
        self.ops.push(Op::SetOutlineColor {
            col: rgb(TEXT.0, TEXT.1, TEXT.2),
        });
        self.ops.push(Op::SetOutlineThickness { pt: Pt(0.8) });
        self.ops.push(Op::DrawLine {
            line: Line {
                points: vec![
                    LinePoint {
                        p: Point {
                            x: Pt(self.left),
                            y: Pt(y),
                        },
                        bezier: false,
                    },
                    LinePoint {
                        p: Point {
                            x: Pt(end),
                            y: Pt(y),
                        },
                        bezier: false,
                    },
                ],
                is_closed: false,
            },
        });
        self.y -= 8.0;
    }

    fn offer_line(&mut self, label: &str, value: &str) {
        if value.trim().is_empty() {
            return;
        }
        self.paragraph(&format!("{label}: {value}"), 10.5, false, TEXT);
    }

    fn badge(&mut self, grade: &Grade) {
        let height = 32.0;
        self.ensure(height + 4.0);
        let y = self.y - height;
        self.rect(self.left, y, self.width(), height, BAND, true);
        self.rect(self.left, y, self.width(), height, RULE, false);
        let saved = self.y;
        self.y = y + height - 8.0;
        self.draw("Grade", self.left + 8.0, 8.0, true, MUTED);
        self.draw(&grade.badge(), self.left + 8.0, 14.0, true, TEXT);
        self.y = saved - height - 4.0;
    }

    fn field(&mut self, label: &str, value: &str) {
        self.paragraph(&format!("{label}: {value}"), 10.0, false, TEXT);
    }

    fn note(&mut self, text: &str) {
        self.paragraph(text, 8.5, false, MUTED);
    }

    fn heading(&mut self, text: &str) {
        self.ensure(64.0);
        self.gap(8.0);
        self.paragraph(text, 14.0, true, TEXT);
        self.hline();
        self.gap(3.0);
    }

    fn paragraph(&mut self, text: &str, size: f32, bold: bool, color: (f32, f32, f32)) {
        let font = if bold { self.bold } else { self.regular };
        for block in text.split('\n') {
            let lines = wrap(font, block, size, self.width());
            let lines = if lines.is_empty() {
                vec![String::new()]
            } else {
                lines
            };
            for line in lines {
                let advance = size * 1.32;
                self.ensure(advance);
                self.draw(&line, self.left, size, bold, color);
            }
        }
    }

    fn gap(&mut self, amount: f32) {
        self.y -= amount;
    }

    fn page_break(&mut self) {
        self.new_page();
    }

    fn draw(&mut self, text: &str, x: f32, size: f32, bold: bool, color: (f32, f32, f32)) {
        let font = if bold { self.bold } else { self.regular };
        let font_id = if bold {
            self.bold_id.clone()
        } else {
            self.regular_id.clone()
        };
        let upem = f32::from(font.units_per_em.max(1));
        let ascent = f32::from(font.font_metrics.ascent.max(0));
        let baseline = self.y - (ascent * size / upem);
        self.ops.push(Op::SetFillColor {
            col: rgb(color.0, color.1, color.2),
        });
        self.ops.push(Op::StartTextSection);
        self.ops.push(Op::SetFont {
            font: PdfFontHandle::External(font_id),
            size: Pt(size),
        });
        self.ops.push(Op::SetTextCursor {
            pos: Point {
                x: Pt(x),
                y: Pt(baseline),
            },
        });
        self.ops.push(Op::ShowText {
            items: vec![TextItem::Text(text.to_string())],
        });
        self.ops.push(Op::EndTextSection);
        self.y -= size * 1.32;
    }

    fn hline(&mut self) {
        self.ensure(4.0);
        self.ops.push(Op::SetOutlineColor {
            col: rgb(RULE.0, RULE.1, RULE.2),
        });
        self.ops.push(Op::SetOutlineThickness { pt: Pt(0.6) });
        let y = self.y;
        self.ops.push(Op::DrawLine {
            line: Line {
                points: vec![
                    LinePoint {
                        p: Point {
                            x: Pt(self.left),
                            y: Pt(y),
                        },
                        bezier: false,
                    },
                    LinePoint {
                        p: Point {
                            x: Pt(self.right),
                            y: Pt(y),
                        },
                        bezier: false,
                    },
                ],
                is_closed: false,
            },
        });
        self.y -= 3.0;
    }

    fn rect(&mut self, x: f32, y: f32, w: f32, h: f32, color: (f32, f32, f32), fill: bool) {
        let col = rgb(color.0, color.1, color.2);
        if fill {
            self.ops.push(Op::SetFillColor { col: col.clone() });
        } else {
            self.ops.push(Op::SetOutlineColor { col });
            self.ops.push(Op::SetOutlineThickness { pt: Pt(0.7) });
        }
        self.ops.push(Op::DrawRectangle {
            rectangle: Rect {
                x: Pt(x),
                y: Pt(y),
                width: Pt(w),
                height: Pt(h),
                mode: Some(if fill {
                    PaintMode::Fill
                } else {
                    PaintMode::Stroke
                }),
                winding_order: None,
            },
        });
    }

    fn table(&mut self, columns: &[(&str, f32)], rows: &[Vec<String>], size: f32) {
        let widths = columns
            .iter()
            .map(|(_, fraction)| self.width() * fraction)
            .collect::<Vec<_>>();
        self.table_row(
            &columns
                .iter()
                .map(|(title, _)| (*title).to_string())
                .collect::<Vec<_>>(),
            &widths,
            size,
            true,
        );
        for row in rows {
            let mut cells = row.clone();
            cells.resize(columns.len(), String::new());
            let height = self.row_height(&cells, &widths, size);
            if self.y - height < self.content_bottom && self.y < self.content_top - 1.0 {
                self.new_page();
                self.table_row(
                    &columns
                        .iter()
                        .map(|(title, _)| (*title).to_string())
                        .collect::<Vec<_>>(),
                    &widths,
                    size,
                    true,
                );
            }
            self.table_row(&cells, &widths, size, false);
        }
    }

    fn table_row(&mut self, cells: &[String], widths: &[f32], size: f32, header: bool) {
        let wrapped = cells
            .iter()
            .zip(widths)
            .map(|(cell, width)| wrap(self.regular, cell, size, (*width - 6.0).max(8.0)))
            .collect::<Vec<_>>();
        let lines = wrapped.iter().map(Vec::len).max().unwrap_or(1).max(1);
        let height = lines as f32 * size * 1.28 + 6.0;
        self.ensure(height);
        let top = self.y;
        let bottom = self.y - height;
        if header {
            self.rect(self.left, bottom, self.width(), height, BAND, true);
        }
        self.ops.push(Op::SetOutlineColor {
            col: rgb(RULE.0, RULE.1, RULE.2),
        });
        self.ops.push(Op::SetOutlineThickness { pt: Pt(0.4) });
        self.ops.push(Op::DrawLine {
            line: Line {
                points: vec![
                    LinePoint {
                        p: Point {
                            x: Pt(self.left),
                            y: Pt(bottom),
                        },
                        bezier: false,
                    },
                    LinePoint {
                        p: Point {
                            x: Pt(self.right),
                            y: Pt(bottom),
                        },
                        bezier: false,
                    },
                ],
                is_closed: false,
            },
        });
        let saved = self.y;
        let mut x = self.left;
        for (index, width) in widths.iter().enumerate() {
            let cell_lines = wrapped.get(index).map(Vec::as_slice).unwrap_or(&[]);
            self.y = top - 2.0;
            for line in cell_lines {
                self.draw(line, x + 3.0, size, header, TEXT);
            }
            x += width;
        }
        self.y = saved - height;
    }

    fn row_height(&self, cells: &[String], widths: &[f32], size: f32) -> f32 {
        let lines = cells
            .iter()
            .zip(widths)
            .map(|(cell, width)| {
                wrap(self.regular, cell, size, (*width - 6.0).max(8.0))
                    .len()
                    .max(1)
            })
            .max()
            .unwrap_or(1);
        lines as f32 * size * 1.28 + 6.0
    }

    fn ensure(&mut self, height: f32) {
        if self.y - height < self.content_bottom && self.y < self.content_top - 1.0 {
            self.new_page();
        }
    }

    fn new_page(&mut self) {
        if self.ops.is_empty() && (self.y - self.content_top).abs() < 0.5 {
            return;
        }
        self.pages.push(std::mem::take(&mut self.ops));
        self.y = self.content_top;
    }

    fn width(&self) -> f32 {
        self.right - self.left
    }

    fn finish(&mut self) -> Vec<Vec<Op>> {
        if !self.ops.is_empty() || self.pages.is_empty() {
            self.pages.push(std::mem::take(&mut self.ops));
        }
        let total = self.pages.len();
        let logo = self.logo.clone();
        for (index, page) in self.pages.iter_mut().enumerate() {
            let mut chrome = Vec::new();
            chrome.extend(accent_bar(self.page_w, self.page_h, self.accent));
            if index == 0 {
                if let Some((id, w, h)) = &logo {
                    chrome.extend(logo_ops(id, *w, *h, self.right, self.content_top));
                }
            }
            chrome.extend(footer(
                &FooterCtx {
                    left: self.left,
                    right: self.right,
                    content_bottom: self.content_bottom,
                    report_id: &self.report_id,
                    font_id: self.regular_id.clone(),
                },
                index + 1,
                total,
            ));
            chrome.extend(std::mem::take(page));
            *page = chrome;
        }
        std::mem::take(&mut self.pages)
    }
}

fn accent_bar(page_w: f32, page_h: f32, accent: (f32, f32, f32)) -> Vec<Op> {
    vec![
        Op::SetFillColor {
            col: rgb(accent.0, accent.1, accent.2),
        },
        Op::DrawRectangle {
            rectangle: Rect {
                x: Pt(0.0),
                y: Pt(page_h - mm(3.2)),
                width: Pt(page_w),
                height: Pt(mm(3.2)),
                mode: Some(PaintMode::Fill),
                winding_order: None,
            },
        },
    ]
}

fn logo_ops(id: &XObjectId, width_px: f32, height_px: f32, right: f32, top: f32) -> Vec<Op> {
    let target = 42.0;
    let dpi = if height_px <= 0.0 {
        96.0
    } else {
        height_px * 72.0 / target
    };
    let width_pt = if height_px <= 0.0 {
        target
    } else {
        target * (width_px / height_px)
    };
    vec![Op::UseXobject {
        id: id.clone(),
        transform: XObjectTransform {
            translate_x: Some(Pt(right - width_pt)),
            translate_y: Some(Pt(top - target)),
            rotate: None,
            scale_x: None,
            scale_y: None,
            dpi: Some(dpi),
        },
    }]
}

struct FooterCtx<'a> {
    left: f32,
    right: f32,
    content_bottom: f32,
    report_id: &'a str,
    font_id: printpdf::FontId,
}

/// The only line of text in the page footer.
pub fn footer_line(report_id: &str, page: usize, total: usize) -> String {
    format!("Weeks IT Solutions · Confidential · {report_id} · Page {page} of {total}")
}

fn footer(ctx: &FooterCtx<'_>, page: usize, total: usize) -> Vec<Op> {
    let mut ops = Vec::new();
    ops.push(Op::SetOutlineColor {
        col: rgb(RULE.0, RULE.1, RULE.2),
    });
    ops.push(Op::SetOutlineThickness { pt: Pt(0.4) });
    let rule_y = ctx.content_bottom - 4.0;
    ops.push(Op::DrawLine {
        line: Line {
            points: vec![
                LinePoint {
                    p: Point {
                        x: Pt(ctx.left),
                        y: Pt(rule_y),
                    },
                    bezier: false,
                },
                LinePoint {
                    p: Point {
                        x: Pt(ctx.right),
                        y: Pt(rule_y),
                    },
                    bezier: false,
                },
            ],
            is_closed: false,
        },
    });
    let line = footer_line(ctx.report_id, page, total);
    ops.extend(text_ops(
        &line,
        ctx.left,
        rule_y - 12.0,
        8.0,
        ctx.font_id.clone(),
        MUTED,
    ));
    ops
}

fn text_ops(
    text: &str,
    x: f32,
    baseline: f32,
    size: f32,
    font_id: printpdf::FontId,
    color: (f32, f32, f32),
) -> Vec<Op> {
    vec![
        Op::SetFillColor {
            col: rgb(color.0, color.1, color.2),
        },
        Op::StartTextSection,
        Op::SetFont {
            font: PdfFontHandle::External(font_id),
            size: Pt(size),
        },
        Op::SetTextCursor {
            pos: Point {
                x: Pt(x),
                y: Pt(baseline),
            },
        },
        Op::ShowText {
            items: vec![TextItem::Text(text.to_string())],
        },
        Op::EndTextSection,
    ]
}

fn wrap(font: &ParsedFont, text: &str, size: f32, max_width: f32) -> Vec<String> {
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        if paragraph.is_empty() {
            lines.push(String::new());
            continue;
        }
        let mut current = String::new();
        for word in paragraph.split_whitespace() {
            let trial = if current.is_empty() {
                word.to_string()
            } else {
                format!("{current} {word}")
            };
            if text_width(font, &trial, size) <= max_width {
                current = trial;
            } else {
                if !current.is_empty() {
                    lines.push(std::mem::take(&mut current));
                }
                if text_width(font, word, size) <= max_width {
                    current = word.to_string();
                } else {
                    let mut chunk = String::new();
                    for ch in word.chars() {
                        let next = format!("{chunk}{ch}");
                        if text_width(font, &next, size) <= max_width || chunk.is_empty() {
                            chunk = next;
                        } else if let Some(pos) = chunk.rfind(['/', '-', '_']) {
                            let (head, tail) = chunk.split_at(pos + 1);
                            lines.push(head.to_string());
                            chunk = format!("{tail}{ch}");
                        } else {
                            lines.push(std::mem::take(&mut chunk));
                            chunk.push(ch);
                        }
                    }
                    current = chunk;
                }
            }
        }
        if !current.is_empty() {
            lines.push(current);
        }
    }
    lines
}

fn text_width(font: &ParsedFont, text: &str, size: f32) -> f32 {
    let upem = f32::from(font.units_per_em.max(1));
    let mut units = 0.0_f32;
    for ch in text.chars() {
        let gid = font.lookup_glyph_index(ch as u32).unwrap_or(0);
        let advance = font.get_glyph_width(gid).unwrap_or(font.units_per_em / 2);
        units += f32::from(advance);
    }
    units * size / upem
}

fn rgb(r: f32, g: f32, b: f32) -> Color {
    Color::Rgb(Rgb::new(r, g, b, None))
}

fn mm(value: f32) -> f32 {
    value * 72.0 / 25.4
}

fn blank(value: &str, fallback: &str) -> String {
    if value.trim().is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

fn count_line(counts: &SeverityCounts) -> String {
    format!(
        "{} {}   {} {}   {} {}   {} {}   {} {}",
        Severity::Critical.tag(),
        counts.critical,
        Severity::High.tag(),
        counts.high,
        Severity::Medium.tag(),
        counts.medium,
        Severity::Low.tag(),
        counts.low,
        Severity::Info.tag(),
        counts.info
    )
}

fn grade_rows(letter: char) -> Vec<Vec<String>> {
    let specs = [
        ('A', "Solid", "✔", "Nothing above low"),
        ('B', "Good, minor fixes", "●", "Up to 3 medium, no high"),
        (
            'C',
            "Needs attention",
            "▲",
            "4 or more medium, or exactly 1 high",
        ),
        ('D', "At risk", "■", "2 or more high"),
        ('F', "Act now", "✖", "Any critical"),
    ];
    specs
        .into_iter()
        .map(|(grade, word, icon, rule)| {
            vec![
                grade.to_string(),
                word.to_string(),
                icon.to_string(),
                rule.to_string(),
                if grade == letter {
                    "Yes".to_string()
                } else {
                    String::new()
                },
            ]
        })
        .collect()
}

const GLOSSARY: &[(&str, &str)] = &[
    (
        "Port",
        "A numbered door on a computer. Web sites usually use 80 and 443. Remote Desktop uses 3389.",
    ),
    (
        "Service",
        "The program listening on a port, such as a web site, mail, or a remote login.",
    ),
    (
        "Banner",
        "The text a service sends when you connect. It often includes the software name and version.",
    ),
    (
        "CVE",
        "A public id for a known security issue, such as CVE-2018-15473. A match on this report means the service may be affected and needs confirming.",
    ),
    (
        "CVSS",
        "A score from 0 to 10 for how serious a known issue is. On this report, 9.0 and above is critical.",
    ),
    (
        "Firewall",
        "A filter that allows or blocks traffic. Closing a port usually means adding a firewall rule.",
    ),
    (
        "Patch",
        "A vendor update that fixes a known issue. Confirm the installed version before assuming one is needed.",
    ),
    (
        "RDP",
        "Remote Desktop. It lets someone control a Windows computer from somewhere else. The usual port is 3389.",
    ),
    (
        "VPN",
        "A private tunnel into a network. A safer way to reach remote login than leaving it on the open internet.",
    ),
    (
        "MFA",
        "Multi-factor login. A second check, such as a phone prompt, so a stolen password is not enough.",
    ),
];

/// Confirms the embedded face can draw every severity and grade shape.
#[cfg(test)]
pub fn embedded_font_has_shapes() -> Result<()> {
    let mut warnings = Vec::new();
    let font = ParsedFont::from_bytes(SANS, 0, &mut warnings)
        .ok_or_else(|| anyhow::anyhow!("DejaVu Sans did not parse: {warnings:?}"))?;
    for ch in ['✔', '●', '▲', '■', '✖', '○', '·'] {
        if font.lookup_glyph_index(ch as u32).is_none() {
            bail!("Embedded DejaVu Sans has no glyph for {ch}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dejavu_contains_the_shape_icons() {
        embedded_font_has_shapes().unwrap();
    }

    #[test]
    fn footer_is_a_single_line() {
        let mut warnings = Vec::new();
        let font = ParsedFont::from_bytes(SANS, 0, &mut warnings).unwrap();
        let line = footer_line("NS-DEMO-0001", 2, 6);
        assert_eq!(line.lines().count(), 1);
        assert!(!line.contains('\n'));
        let width = mm(210.0) - mm(32.0);
        assert_eq!(wrap(&font, &line, 8.0, width).len(), 1, "{line}");
    }
}
