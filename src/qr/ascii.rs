use qrcode::{Color, QrCode};

/// Render a QR code in the same style as the `qrcode-terminal` npm
/// package's "small" mode — the renderer every Baileys example uses.
///
/// Two module rows are compressed into one terminal line using Unicode
/// half blocks. Colours are inverted so the QR reads correctly on a
/// terminal with a dark background: light QR modules print as `█`
/// (FULL BLOCK, rendered in the foreground colour — typically white)
/// and dark QR modules print as a space (showing the terminal
/// background). A 1-module-wide quiet-zone column is added on each
/// side, plus a half-block border top and bottom.
pub fn render_qr(data: &[u8]) -> String {
    let code = QrCode::new(data).expect("valid QR data");
    let width = code.width();
    let colors = code.to_colors();

    // `true` = light module (WHITE in qrcode-terminal terminology),
    // `false` = dark module (BLACK, i.e. part of the QR pattern).
    let mut rows: Vec<Vec<bool>> = (0..width)
        .map(|y| (0..width).map(|x| colors[y * width + x] != Color::Dark).collect())
        .collect();

    // qrcode-terminal pads a final WHITE row when there's an odd count,
    // otherwise the last pair would read half of someone else's memory.
    let odd = width % 2 == 1;
    if odd {
        rows.push(vec![true; width]);
    }

    // Chars — same palette as qrcode-terminal's `small` mode.
    const WHITE_ALL:  char = '\u{2588}'; // █ — top light, bottom light
    const WHITE_BLACK: char = '\u{2580}'; // ▀ — top light, bottom dark
    const BLACK_WHITE: char = '\u{2584}'; // ▄ — top dark,  bottom light
    const BLACK_ALL:  char = ' ';         //   — top dark,  bottom dark

    let mut out = String::new();

    // Top border: the `▄` character draws a 1-module-wide border that looks
    // like a light strip sitting on the QR (bottom half light = quiet zone
    // row just above the first module row).
    for _ in 0..(width + 2) { out.push(BLACK_WHITE); }
    out.push('\n');

    let mut y = 0;
    while y + 1 < rows.len() {
        out.push(WHITE_ALL); // left quiet-zone column
        for x in 0..width {
            let top    = rows[y][x];
            let bottom = rows[y + 1][x];
            let ch = match (top, bottom) {
                (true,  true)  => WHITE_ALL,
                (true,  false) => WHITE_BLACK,
                (false, true)  => BLACK_WHITE,
                (false, false) => BLACK_ALL,
            };
            out.push(ch);
        }
        out.push(WHITE_ALL); // right quiet-zone column
        out.push('\n');
        y += 2;
    }

    // Bottom border only when the row count was even — otherwise the padded
    // final WHITE row already serves as the bottom quiet zone.
    if !odd {
        for _ in 0..(width + 2) { out.push(WHITE_BLACK); }
        out.push('\n');
    }

    out
}
