const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, VerticalAlign, PageNumber, LevelFormat, TableOfContents,
  PageBreak, Bookmark, InternalHyperlink, SectionType
} = require("docx");
const fs = require("fs");

// ── Read & strip ALL code blocks ─────────────────────────────────────────────
const raw    = fs.readFileSync("RA_TechStack_Tables.md", "utf8");
const noCode = raw.replace(/```[\s\S]*?```/g, "");
const lines  = noCode.split(/\r?\n/);

// ── Colour palette ───────────────────────────────────────────────────────────
const C = {
  navyDark   : "1F3864",
  blueMid    : "2E75B6",
  blueLt     : "4472C4",
  headerCell : "D5E8F0",
  altRow     : "F5F9FC",
  white      : "FFFFFF",
  black      : "000000",
  quoteBg    : "EBF3FB",
  accent     : "2E75B6",
  footerTxt  : "7F7F7F",
  red        : "C00000",
};

// DXA constants (1 inch = 1440 DXA)
const PAGE_W    = 12240;   // 8.5 in
const PAGE_H    = 15840;   // 11 in
const MARGIN    = 1080;    // 0.75 in
const CONTENT_W = PAGE_W - MARGIN * 2;   // 10080

// ── Helper: single border object ────────────────────────────────────────────
const singleBorder = (color, size = 1) => ({
  style: BorderStyle.SINGLE, size, color
});
const cellBorders = (color = "BBBBBB") => {
  const b = singleBorder(color);
  return { top: b, bottom: b, left: b, right: b };
};

// ── Inline markdown → TextRun[] ─────────────────────────────────────────────
function parseInline(text, baseSize = 20, baseColor = C.black) {
  text = text.replace(/^\||\|$/g, "").trim();
  const runs = [];
  const re   = /(\*\*\*(.+?)\*\*\*|\*\*(.+?)\*\*|`([^`]+)`|\*(.+?)\*|_(.+?)_)/g;
  let last = 0, m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last)
      runs.push(new TextRun({ text: text.slice(last, m.index), font: "Calibri", size: baseSize, color: baseColor }));
    if (m[2])
      runs.push(new TextRun({ text: m[2], bold: true, italics: true,  font: "Calibri",    size: baseSize,   color: baseColor }));
    else if (m[3])
      runs.push(new TextRun({ text: m[3], bold: true,                 font: "Calibri",    size: baseSize,   color: baseColor }));
    else if (m[4])
      runs.push(new TextRun({ text: m[4],                             font: "Courier New",size: baseSize-2, color: "C7254E"  }));
    else if (m[5] || m[6])
      runs.push(new TextRun({ text: m[5]||m[6], italics: true,        font: "Calibri",    size: baseSize,   color: baseColor }));
    last = m.index + m[0].length;
  }
  if (last < text.length)
    runs.push(new TextRun({ text: text.slice(last), font: "Calibri", size: baseSize, color: baseColor }));
  return runs.length ? runs : [new TextRun({ text, font: "Calibri", size: baseSize, color: baseColor })];
}

// ── Table builder ─────────────────────────────────────────────────────────────
function buildTable(tableLines) {
  const dataRows = tableLines.filter(
    l => l.trim().startsWith("|") && !/^\|[-:\s|]+\|$/.test(l.trim())
  );
  if (!dataRows.length) return null;

  const numCols = Math.max(...dataRows.map(
    r => r.split("|").filter((_, i, a) => i > 0 && i < a.length - 1).length
  ));
  if (numCols === 0) return null;

  const colW     = Math.floor(CONTENT_W / numCols);
  const colWidths = Array(numCols).fill(colW);

  const rows = dataRows.map((row, ri) => {
    const cells    = row.split("|").filter((_, i, a) => i > 0 && i < a.length - 1);
    const isHeader = ri === 0;
    const isAlt    = !isHeader && ri % 2 === 0;
    const fill     = isHeader ? C.headerCell : (isAlt ? C.altRow : C.white);

    return new TableRow({
      tableHeader: isHeader,
      children: Array.from({ length: numCols }, (_, ci) => {
        const txt = (cells[ci] || "").trim();
        return new TableCell({
          borders        : cellBorders(),
          width          : { size: colWidths[ci], type: WidthType.DXA },
          shading        : { fill, type: ShadingType.CLEAR },
          margins        : { top: 70, bottom: 70, left: 110, right: 110 },
          verticalAlign  : VerticalAlign.CENTER,
          children       : [new Paragraph({
            children  : parseInline(txt, isHeader ? 18 : 19),
            spacing   : { before: 20, after: 20 },
            alignment : isHeader ? AlignmentType.CENTER : AlignmentType.LEFT,
          })],
        });
      }),
    });
  });

  return new Table({
    width      : { size: CONTENT_W, type: WidthType.DXA },
    columnWidths: colWidths,
    rows,
  });
}

// ── Shared page properties ───────────────────────────────────────────────────
const pageProps = {
  page: {
    size  : { width: PAGE_W, height: PAGE_H },
    margin: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN },
  }
};

// ── Header / Footer ──────────────────────────────────────────────────────────
const mainHeader = new Header({
  children: [new Paragraph({
    children: [
      new TextRun({ text: "RA System — Technology Stack Reference Tables  |  ",
        font: "Calibri", size: 16, color: C.footerTxt }),
      new TextRun({ text: "CONFIDENTIAL — INTERNAL USE ONLY",
        font: "Calibri", size: 16, bold: true, color: C.red }),
    ],
    border : { bottom: singleBorder(C.accent, 6) },
    spacing: { after: 80 },
  })],
});

const mainFooter = new Footer({
  children: [new Paragraph({
    children: [
      new TextRun({ text: "PKI Architecture Team  \u2022  v2.2  \u2022  2026-03-16  \u2022  Page ",
        font: "Calibri", size: 16, color: C.footerTxt }),
      new TextRun({ children: [PageNumber.CURRENT], font: "Calibri", size: 16, color: C.footerTxt }),
      new TextRun({ text: " of ", font: "Calibri", size: 16, color: C.footerTxt }),
      new TextRun({ children: [PageNumber.TOTAL_PAGES], font: "Calibri", size: 16, color: C.footerTxt }),
    ],
    alignment: AlignmentType.RIGHT,
    border   : { top: singleBorder(C.accent, 6) },
    spacing  : { before: 80 },
  })],
});

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 1 — COVER PAGE
// ═══════════════════════════════════════════════════════════════════════════
const coverChildren = [
  // Top spacer
  ...Array(8).fill(null).map(() => new Paragraph({ children: [new TextRun("")] })),

  // Logo-style accent bar
  new Paragraph({
    children: [new TextRun("")],
    border  : { bottom: { style: BorderStyle.THICK, size: 24, color: C.navyDark } },
    spacing : { after: 480 },
  }),

  // Main title
  new Paragraph({
    alignment: AlignmentType.CENTER,
    children : [new TextRun({
      text: "Registration Authority (RA) System",
      font: "Calibri", size: 64, bold: true, color: C.navyDark,
    })],
    spacing: { after: 160 },
  }),

  new Paragraph({
    alignment: AlignmentType.CENTER,
    children : [new TextRun({
      text: "Technology Stack Reference Tables",
      font: "Calibri", size: 44, bold: true, color: C.blueMid,
    })],
    spacing: { after: 480 },
  }),

  // Meta info table
  new Table({
    width      : { size: 6000, type: WidthType.DXA },
    columnWidths: [2200, 3800],
    rows: [
      ["Version",     "2.2"],
      ["Date",        "16 March 2026"],
      ["Project",     "PKI Registration Authority"],
      ["Base Stack",  "Java 21 LTS + Spring Boot 4.0.3"],
      ["Build Tool",  "Gradle 9.4.0 (Kotlin DSL)"],
      ["Framework",   "Spring Framework 7.0.6"],
      ["Status",      "CONFIDENTIAL — Internal Use Only"],
    ].map(([label, value], i) => new TableRow({
      children: [
        new TableCell({
          borders: cellBorders("DDDDDD"),
          width  : { size: 2200, type: WidthType.DXA },
          shading: { fill: C.navyDark, type: ShadingType.CLEAR },
          margins: { top: 80, bottom: 80, left: 120, right: 120 },
          children: [new Paragraph({
            children : [new TextRun({ text: label, bold: true, font: "Calibri", size: 20, color: C.white })],
            alignment: AlignmentType.LEFT,
          })],
        }),
        new TableCell({
          borders: cellBorders("DDDDDD"),
          width  : { size: 3800, type: WidthType.DXA },
          shading: { fill: i % 2 === 0 ? "F0F4F8" : C.white, type: ShadingType.CLEAR },
          margins: { top: 80, bottom: 80, left: 120, right: 120 },
          children: [new Paragraph({
            children: [new TextRun({
              text  : value,
              font  : "Calibri",
              size  : 20,
              bold  : label === "Status",
              color : label === "Status" ? C.red : C.black,
            })],
          })],
        }),
      ],
    })),
  }),

  // Bottom accent bar
  ...Array(6).fill(null).map(() => new Paragraph({ children: [new TextRun("")] })),
  new Paragraph({
    children: [new TextRun("")],
    border  : { bottom: { style: BorderStyle.THICK, size: 24, color: C.blueMid } },
  }),

  new Paragraph({
    alignment: AlignmentType.CENTER,
    children : [new TextRun({
      text: "PKI Architecture Team  \u2022  Internal Use Only  \u2022  Do Not Distribute",
      font: "Calibri", size: 16, italics: true, color: C.footerTxt,
    })],
    spacing: { before: 120 },
  }),
];

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 2 — TABLE OF CONTENTS
// ═══════════════════════════════════════════════════════════════════════════
const tocChildren = [
  // TOC heading
  new Paragraph({
    alignment: AlignmentType.CENTER,
    children : [new TextRun({
      text: "Table of Contents",
      font: "Calibri", size: 44, bold: true, color: C.navyDark,
    })],
    spacing: { before: 240, after: 120 },
    border : { bottom: singleBorder(C.blueMid, 8) },
  }),

  new Paragraph({ children: [new TextRun("")], spacing: { after: 120 } }),

  // Native Word TOC field — hyperlink: true enables Ctrl+Click navigation
  // headingStyleRange: "1-4" picks up H1 (doc title), H2 (sections), H3 (subsections), H4 (each table)
  // Press Ctrl+A → F9 in Word to update page numbers
  new TableOfContents("Table of Contents", {
    hyperlink          : true,
    headingStyleRange  : "1-4",
    stylesWithLevels   : [
      { styleId: "Heading1", level: 1 },
      { styleId: "Heading2", level: 2 },
      { styleId: "Heading3", level: 3 },
      { styleId: "Heading4", level: 4 },
    ],
  }),

  new Paragraph({ children: [new TextRun("")], spacing: { after: 240 } }),

  // Instructions note
  new Paragraph({
    children: [new TextRun({
      text: "\u26A0\uFE0F  To update page numbers: open in Microsoft Word \u2192 press Ctrl+A \u2192 press F9 \u2192 select \u201CUpdate entire table\u201D",
      font: "Calibri", size: 17, italics: true, color: "8B6914",
    })],
    shading: { fill: "FFFBE6", type: ShadingType.CLEAR },
    border : {
      top   : singleBorder("F0C040", 4),
      bottom: singleBorder("F0C040", 4),
      left  : { style: BorderStyle.THICK, size: 8, color: "F0C040" },
      right : singleBorder("F0C040", 4),
    },
    indent : { left: 200, right: 200 },
    spacing: { before: 80, after: 80 },
  }),
];

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 3 — MAIN CONTENT  (parsed from markdown)
// ═══════════════════════════════════════════════════════════════════════════
const mainChildren = [];
let inCode = false, codeLines = [], tableLines = [], inTable = false;

function flushTable() {
  if (tableLines.length) {
    const tbl = buildTable(tableLines);
    if (tbl) {
      mainChildren.push(tbl);
      mainChildren.push(new Paragraph({ children: [new TextRun("")], spacing: { before: 100 } }));
    }
  }
  tableLines = []; inTable = false;
}
function flushCode() { codeLines = []; inCode = false; }

// Bookmark counter — unique ID per heading for TOC hyperlinks
let bmId = 0;
function headingBookmarkId(text) {
  return "h_" + text.toLowerCase().replace(/[^a-z0-9]+/g, "_").slice(0, 40) + "_" + (bmId++);
}

for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  const trim = line.trim();

  // ── Code fence (already stripped, but guard for any residual) ──────────
  if (!inCode && trim.startsWith("```")) { flushTable(); inCode = true; codeLines = []; continue; }
  if (inCode)  { if (trim === "```") flushCode(); else codeLines.push(line); continue; }

  // ── Table rows ─────────────────────────────────────────────────────────
  if (trim.startsWith("|")) { inTable = true; tableLines.push(trim); continue; }
  if (inTable) flushTable();

  // ── H4 ─────────────────────────────────────────────────────────────────
  if (trim.startsWith("#### ")) {
    const text = trim.slice(5);
    mainChildren.push(new Paragraph({
      heading : HeadingLevel.HEADING_4,
      children: [new Bookmark({ id: headingBookmarkId(text), children: parseInline(text, 19, C.navyDark) })],
      spacing : { before: 160, after: 80 },
    }));
    continue;
  }

  // ── H3 ─────────────────────────────────────────────────────────────────
  if (trim.startsWith("### ")) {
    const text = trim.slice(4);
    mainChildren.push(new Paragraph({
      heading : HeadingLevel.HEADING_3,
      children: [new Bookmark({
        id      : headingBookmarkId(text),
        children: [new TextRun({ text, bold: true, font: "Calibri", size: 22, color: C.white })],
      })],
      shading : { fill: C.blueLt, type: ShadingType.CLEAR },
      spacing : { before: 200, after: 100 },
      indent  : { left: 120 },
    }));
    continue;
  }

  // ── H2 ─────────────────────────────────────────────────────────────────
  if (trim.startsWith("## ")) {
    flushTable();
    const text = trim.slice(3);
    mainChildren.push(new Paragraph({ children: [new PageBreak()] }));
    mainChildren.push(new Paragraph({
      heading : HeadingLevel.HEADING_2,
      children: [new Bookmark({
        id      : headingBookmarkId(text),
        children: [new TextRun({ text, bold: true, font: "Calibri", size: 26, color: C.white })],
      })],
      shading : { fill: C.blueMid, type: ShadingType.CLEAR },
      spacing : { before: 240, after: 160 },
      indent  : { left: 120 },
    }));
    continue;
  }

  // ── H1 ─────────────────────────────────────────────────────────────────
  if (trim.startsWith("# ")) {
    const text = trim.slice(2);
    mainChildren.push(new Paragraph({
      heading : HeadingLevel.HEADING_1,
      children: [new Bookmark({
        id      : headingBookmarkId(text),
        children: [new TextRun({ text, bold: true, font: "Calibri", size: 32, color: C.white })],
      })],
      shading : { fill: C.navyDark, type: ShadingType.CLEAR },
      spacing : { before: 280, after: 200 },
      indent  : { left: 120 },
    }));
    continue;
  }

  // ── Blockquote ─────────────────────────────────────────────────────────
  if (trim.startsWith("> ")) {
    mainChildren.push(new Paragraph({
      children: parseInline(trim.slice(2), 19, "1A4A6E"),
      shading : { fill: C.quoteBg, type: ShadingType.CLEAR },
      indent  : { left: 400 },
      spacing : { before: 80, after: 80 },
      border  : { left: { style: BorderStyle.THICK, size: 8, color: C.blueMid } },
    }));
    continue;
  }

  // ── HR ─────────────────────────────────────────────────────────────────
  if (/^---+$/.test(trim)) {
    mainChildren.push(new Paragraph({
      children: [new TextRun("")],
      spacing : { before: 60, after: 60 },
      border  : { bottom: singleBorder("CCCCCC", 2) },
    }));
    continue;
  }

  // ── Bullet list ────────────────────────────────────────────────────────
  if (trim.startsWith("- ")) {
    mainChildren.push(new Paragraph({
      numbering: { reference: "bullets", level: 0 },
      children : parseInline(trim.slice(2)),
      spacing  : { before: 40, after: 40 },
    }));
    continue;
  }

  // ── Empty line ─────────────────────────────────────────────────────────
  if (trim === "") {
    mainChildren.push(new Paragraph({ children: [new TextRun("")], spacing: { before: 40 } }));
    continue;
  }

  // ── Normal paragraph ───────────────────────────────────────────────────
  mainChildren.push(new Paragraph({
    children: parseInline(trim),
    spacing : { before: 60, after: 60 },
  }));
}

flushTable();
flushCode();

// ═══════════════════════════════════════════════════════════════════════════
// DOCUMENT ASSEMBLY
// ═══════════════════════════════════════════════════════════════════════════
const doc = new Document({
  creator    : "PKI Architecture Team",
  title      : "RA System — Technology Stack Reference Tables",
  description: "Complete PKI RA tech stack: 30 sections, all LTS versions verified March 2026",
  keywords   : "PKI, RA, PQC, Spring Boot, Java 21, Gradle, BouncyCastle",

  numbering: {
    config: [{
      reference: "bullets",
      levels   : [{
        level    : 0,
        format   : LevelFormat.BULLET,
        text     : "\u2022",
        alignment: AlignmentType.LEFT,
        style    : { paragraph: { indent: { left: 720, hanging: 360 } } },
      }],
    }],
  },

  styles: {
    default: {
      document: { run: { font: "Calibri", size: 20, color: C.black } },
    },
    paragraphStyles: [
      {
        id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 32, bold: true, font: "Calibri", color: C.white },
        paragraph: { spacing: { before: 280, after: 200 }, outlineLevel: 0 },
      },
      {
        id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 26, bold: true, font: "Calibri", color: C.white },
        paragraph: { spacing: { before: 240, after: 160 }, outlineLevel: 1 },
      },
      {
        id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 22, bold: true, font: "Calibri", color: C.white },
        paragraph: { spacing: { before: 200, after: 100 }, outlineLevel: 2 },
      },
      {
        id: "Heading4", name: "Heading 4", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 20, bold: true, font: "Calibri", color: C.navyDark },
        paragraph: { spacing: { before: 160, after: 80 }, outlineLevel: 3 },
      },
    ],
  },

  sections: [
    // ── Cover page — no header/footer, own page ──────────────────────────
    {
      properties: {
        ...pageProps,
        type: SectionType.NEXT_PAGE,
      },
      children: coverChildren,
    },
    // ── TOC page — with header/footer ────────────────────────────────────
    {
      properties: {
        ...pageProps,
        type: SectionType.NEXT_PAGE,
      },
      headers: { default: mainHeader },
      footers: { default: mainFooter },
      children: tocChildren,
    },
    // ── Main content ─────────────────────────────────────────────────────
    {
      properties: {
        ...pageProps,
        type: SectionType.NEXT_PAGE,
      },
      headers: { default: mainHeader },
      footers: { default: mainFooter },
      children: mainChildren,
    },
  ],
});

// ── Write output ─────────────────────────────────────────────────────────────
Packer.toBuffer(doc).then(buf => {
  fs.writeFileSync("RA_TechStack_Reference.docx", buf);
  console.log("✅  RA_TechStack_Reference.docx  —  " + (buf.length / 1024).toFixed(1) + " KB");
  console.log("📌  Open in Word → Ctrl+A → F9 → 'Update entire table' to refresh TOC page numbers");
}).catch(err => { console.error("ERROR:", err.message); process.exit(1); });
