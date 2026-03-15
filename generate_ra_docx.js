const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, VerticalAlign, PageNumber, LevelFormat, TableOfContents,
  PageBreak
} = require("docx");
const fs = require("fs");

// ── Read & clean source ──────────────────────────────────────────────────────
const raw = fs.readFileSync("RA_TechStack_Tables.md", "utf8");

// Strip ALL code blocks (```any-language ... ```) — tech stack tables only
const noCode = raw.replace(/```[\s\S]*?```/g, "");

const lines = noCode.split(/\r?\n/);

// ── Colour palette ───────────────────────────────────────────────────────────
const C = {
  heading1Bg : "1F3864",   // dark navy
  heading2Bg : "2E75B6",   // mid blue
  heading3Bg : "4472C4",   // lighter blue
  headerCell : "D5E8F0",   // table column header (light blue)
  altRow     : "F5F9FC",   // zebra stripe
  white      : "FFFFFF",
  black      : "000000",
  codeBg     : "F4F4F4",
  quoteBg    : "FFF8DC",   // warm yellow for blockquotes
  accent     : "2E75B6",
  footerText : "7F7F7F",
};

const CONTENT_W = 9360;  // US Letter minus 1-inch margins (DXA)

// ── Border helpers ───────────────────────────────────────────────────────────
function cellBorder(color = "CCCCCC") {
  const b = { style: BorderStyle.SINGLE, size: 1, color };
  return { top: b, bottom: b, left: b, right: b };
}

// ── Inline markdown parser → TextRun[] ──────────────────────────────────────
function parseInline(text) {
  const runs = [];
  // strip leading/trailing pipe characters in table cells
  text = text.replace(/^\||\|$/g, "").trim();

  const re = /(\*\*\*(.+?)\*\*\*|\*\*(.+?)\*\*|`([^`]+)`|\*(.+?)\*|_(.+?)_)/g;
  let last = 0, m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) runs.push(new TextRun({ text: text.slice(last, m.index), font: "Calibri", size: 20 }));
    if (m[2]) runs.push(new TextRun({ text: m[2], bold: true, italics: true, font: "Calibri", size: 20 }));
    else if (m[3]) runs.push(new TextRun({ text: m[3], bold: true, font: "Calibri", size: 20 }));
    else if (m[4]) runs.push(new TextRun({ text: m[4], font: "Courier New", size: 18, color: "C7254E" }));
    else if (m[5] || m[6]) runs.push(new TextRun({ text: m[5] || m[6], italics: true, font: "Calibri", size: 20 }));
    last = m.index + m[0].length;
  }
  if (last < text.length) runs.push(new TextRun({ text: text.slice(last), font: "Calibri", size: 20 }));
  return runs.length ? runs : [new TextRun({ text, font: "Calibri", size: 20 })];
}

// ── Table builder ────────────────────────────────────────────────────────────
function buildTable(tableLines) {
  const rows = tableLines.filter(l => l.trim().startsWith("|") && !/^\|[-: |]+\|/.test(l.trim()));
  if (rows.length === 0) return null;

  const colCounts = rows.map(r => r.split("|").filter((_, i, a) => i > 0 && i < a.length - 1).length);
  const numCols = Math.max(...colCounts);
  if (numCols === 0) return null;

  const colW = Math.floor(CONTENT_W / numCols);
  const colWidths = Array(numCols).fill(colW);

  const tableRows = rows.map((row, ri) => {
    const cells = row.split("|").filter((_, i, a) => i > 0 && i < a.length - 1);
    const isHeader = ri === 0;
    const isAlt    = !isHeader && ri % 2 === 0;

    const tcells = Array.from({ length: numCols }, (_, ci) => {
      const cellText = (cells[ci] || "").trim();
      const fillColor = isHeader ? C.headerCell : (isAlt ? C.altRow : C.white);

      return new TableCell({
        borders: cellBorder("BBBBBB"),
        width: { size: colWidths[ci], type: WidthType.DXA },
        shading: { fill: fillColor, type: ShadingType.CLEAR },
        margins: { top: 60, bottom: 60, left: 100, right: 100 },
        verticalAlign: VerticalAlign.CENTER,
        children: [new Paragraph({
          children: parseInline(cellText),
          spacing: { before: 20, after: 20 },
          ...(isHeader ? { alignment: AlignmentType.CENTER } : {})
        })]
      });
    });

    return new TableRow({
      children: tcells,
      tableHeader: isHeader,
    });
  });

  return new Table({
    width: { size: CONTENT_W, type: WidthType.DXA },
    columnWidths: colWidths,
    rows: tableRows,
  });
}

// ── Main parser ──────────────────────────────────────────────────────────────
const children = [];

// Cover page
children.push(
  new Paragraph({
    children: [new PageBreak()],
  })
);

// Title + meta (will be replaced by proper first section)
let inCode   = false;
let codeLang = "";
let codeLines = [];
let tableLines = [];
let inTable  = false;

function flushTable() {
  if (tableLines.length > 0) {
    const tbl = buildTable(tableLines);
    if (tbl) {
      children.push(tbl);
      children.push(new Paragraph({ children: [new TextRun("")], spacing: { before: 80 } }));
    }
    tableLines = [];
  }
  inTable = false;
}

function flushCode() {
  // Code blocks are fully stripped — nothing to render
  codeLines = [];
  inCode    = false;
  codeLang  = "";
}

for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  const trim = line.trim();

  // ── Code block detection ───────────────────────────────────────────────
  if (!inCode && trim.startsWith("```")) {
    flushTable();
    codeLang = trim.slice(3).toLowerCase().trim();
    inCode = true;
    codeLines = [];
    continue;
  }
  if (inCode) {
    if (trim === "```") {
      flushCode();
    } else {
      codeLines.push(line);
    }
    continue;
  }

  // ── Table row ─────────────────────────────────────────────────────────
  if (trim.startsWith("|")) {
    inTable = true;
    tableLines.push(trim);
    continue;
  } else if (inTable) {
    flushTable();
  }

  // ── Headings ──────────────────────────────────────────────────────────
  if (trim.startsWith("#### ")) {
    const text = trim.slice(5);
    children.push(new Paragraph({
      heading: HeadingLevel.HEADING_4,
      children: parseInline(text),
      spacing: { before: 160, after: 80 }
    }));
    continue;
  }
  if (trim.startsWith("### ")) {
    const text = trim.slice(4);
    children.push(new Paragraph({
      heading: HeadingLevel.HEADING_3,
      children: [new TextRun({ text, bold: true, color: C.white, font: "Calibri", size: 22 })],
      shading : { fill: C.heading3Bg, type: ShadingType.CLEAR },
      spacing : { before: 200, after: 100 },
      indent  : { left: 120 }
    }));
    continue;
  }
  if (trim.startsWith("## ")) {
    flushTable();
    const text = trim.slice(3);
    children.push(new Paragraph({ children: [new PageBreak()] }));
    children.push(new Paragraph({
      heading: HeadingLevel.HEADING_2,
      children: [new TextRun({ text, bold: true, color: C.white, font: "Calibri", size: 26 })],
      shading : { fill: C.heading2Bg, type: ShadingType.CLEAR },
      spacing : { before: 240, after: 160 },
      indent  : { left: 120 }
    }));
    continue;
  }
  if (trim.startsWith("# ")) {
    const text = trim.slice(2);
    children.push(new Paragraph({
      heading: HeadingLevel.HEADING_1,
      children: [new TextRun({ text, bold: true, color: C.white, font: "Calibri", size: 32 })],
      shading : { fill: C.heading1Bg, type: ShadingType.CLEAR },
      spacing : { before: 280, after: 200 },
      indent  : { left: 120 }
    }));
    continue;
  }

  // ── Blockquote ────────────────────────────────────────────────────────
  if (trim.startsWith("> ")) {
    const text = trim.slice(2);
    children.push(new Paragraph({
      children: parseInline(text),
      shading : { fill: C.quoteBg, type: ShadingType.CLEAR },
      indent  : { left: 440 },
      spacing : { before: 80, after: 80 },
      border  : {
        left: { style: BorderStyle.THICK, size: 6, color: "D4A017" }
      }
    }));
    continue;
  }

  // ── HR ────────────────────────────────────────────────────────────────
  if (/^---+$/.test(trim)) {
    children.push(new Paragraph({
      children: [new TextRun("")],
      spacing : { before: 60, after: 60 },
      border  : { bottom: { style: BorderStyle.SINGLE, size: 2, color: "CCCCCC", space: 1 } }
    }));
    continue;
  }

  // ── Bold metadata lines (**X:** Y) ────────────────────────────────────
  if (/^\*\*[A-Za-z ]+:\*\*/.test(trim)) {
    children.push(new Paragraph({
      children: parseInline(trim),
      spacing : { before: 60, after: 40 }
    }));
    continue;
  }

  // ── Bullet / list items ───────────────────────────────────────────────
  if (trim.startsWith("- ")) {
    children.push(new Paragraph({
      numbering: { reference: "bullets", level: 0 },
      children : parseInline(trim.slice(2)),
      spacing  : { before: 40, after: 40 }
    }));
    continue;
  }

  // ── ASCII art / plain text / empty ────────────────────────────────────
  if (trim === "" || trim === "---") {
    children.push(new Paragraph({ children: [new TextRun("")], spacing: { before: 60 } }));
    continue;
  }

  // ── Normal paragraph ──────────────────────────────────────────────────
  children.push(new Paragraph({
    children: parseInline(trim),
    spacing : { before: 60, after: 60 }
  }));
}

flushTable();
flushCode();

// ── Document assembly ────────────────────────────────────────────────────────
const doc = new Document({
  creator: "PKI Architecture Team",
  title  : "RA System — Technology Stack Reference",
  description: "Complete tech stack tables for the Registration Authority system",

  numbering: {
    config: [{
      reference: "bullets",
      levels: [{
        level    : 0,
        format   : LevelFormat.BULLET,
        text     : "\u2022",
        alignment: AlignmentType.LEFT,
        style    : { paragraph: { indent: { left: 720, hanging: 360 } } }
      }]
    }]
  },

  styles: {
    default: {
      document: { run: { font: "Calibri", size: 20, color: C.black } }
    },
    paragraphStyles: [
      {
        id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 32, bold: true, font: "Calibri", color: C.white },
        paragraph: { spacing: { before: 280, after: 200 }, outlineLevel: 0 }
      },
      {
        id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 26, bold: true, font: "Calibri", color: C.white },
        paragraph: { spacing: { before: 240, after: 160 }, outlineLevel: 1 }
      },
      {
        id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 22, bold: true, font: "Calibri", color: C.white },
        paragraph: { spacing: { before: 200, after: 100 }, outlineLevel: 2 }
      },
      {
        id: "Heading4", name: "Heading 4", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 20, bold: true, font: "Calibri", color: "1F3864" },
        paragraph: { spacing: { before: 160, after: 80 }, outlineLevel: 3 }
      },
    ]
  },

  sections: [{
    properties: {
      page: {
        size  : { width: 12240, height: 15840 },
        margin: { top: 1080, right: 1080, bottom: 1080, left: 1080 }
      }
    },
    headers: {
      default: new Header({
        children: [new Paragraph({
          children: [
            new TextRun({ text: "RA System — Technology Stack Reference  |  ", font: "Calibri", size: 16, color: C.footerText }),
            new TextRun({ text: "CONFIDENTIAL — INTERNAL USE ONLY", font: "Calibri", size: 16, bold: true, color: "C00000" }),
          ],
          border : { bottom: { style: BorderStyle.SINGLE, size: 4, color: C.accent, space: 1 } },
          spacing: { after: 60 }
        })]
      })
    },
    footers: {
      default: new Footer({
        children: [new Paragraph({
          children: [
            new TextRun({ text: "PKI Architecture Team  |  v2.1  |  2026-03-15  |  Page ", font: "Calibri", size: 16, color: C.footerText }),
            new TextRun({ children: [PageNumber.CURRENT], font: "Calibri", size: 16, color: C.footerText }),
            new TextRun({ text: " of ", font: "Calibri", size: 16, color: C.footerText }),
            new TextRun({ children: [PageNumber.TOTAL_PAGES], font: "Calibri", size: 16, color: C.footerText }),
          ],
          alignment: AlignmentType.RIGHT,
          border   : { top: { style: BorderStyle.SINGLE, size: 4, color: C.accent, space: 1 } },
          spacing  : { before: 60 }
        })]
      })
    },
    children
  }]
});

// ── Write file ───────────────────────────────────────────────────────────────
Packer.toBuffer(doc).then(buf => {
  const outPath = "RA_TechStack_Reference.docx";
  fs.writeFileSync(outPath, buf);
  console.log("✅  Created: " + outPath + "  (" + (buf.length / 1024).toFixed(1) + " KB)");
}).catch(err => {
  console.error("ERROR:", err.message);
  process.exit(1);
});
