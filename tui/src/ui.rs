use crate::app::{AppState, ChatLine, Focus};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Main draw function — called every render tick.
/// Takes a reference to AppState (read-only) and the ratatui Frame.
pub fn draw(f: &mut Frame, state: &AppState) {
    let area = f.area();

    // Split vertically: [top_area, input_area (3 lines), status_area (1 line)]
    let [top_area, input_area, status_area] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .areas(area);

    // Split top_area horizontally: [users_area (20%), chat_area (80%)]
    let [users_area, chat_area] =
        Layout::horizontal([Constraint::Percentage(20), Constraint::Fill(1)]).areas(top_area);

    draw_users(f, users_area, state);
    draw_chat(f, chat_area, state);

    // Compute the visible tail of the input string that keeps the cursor in view.
    let visible_width = input_area.width.saturating_sub(2) as usize;
    let display_start = find_display_start(&state.input, state.input_cursor, visible_width);
    draw_input(f, input_area, state, display_start);

    draw_status(f, status_area, state);

    // Position cursor in input box when input is focused.
    if state.focus == Focus::Input {
        let display_cursor_col =
            UnicodeWidthStr::width(&state.input[display_start..state.input_cursor]) as u16;
        f.set_cursor_position((input_area.x + 1 + display_cursor_col, input_area.y + 1));
    }
}

fn draw_users(f: &mut Frame, area: Rect, state: &AppState) {
    let border_style = if state.focus == Focus::UserList {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    let block = Block::default()
        .title("Online")
        .borders(Borders::ALL)
        .border_style(border_style);

    // Build display list — show in connection order (which maintains admin at [0]),
    // marking the admin with [A]. Never sort state.online in place (admin election invariant).
    let items: Vec<ListItem> = state
        .online
        .iter()
        .enumerate()
        .map(|(i, user)| {
            let name = state.display_name(&user.pub_id);
            let prefix = if i == 0 { "[A] " } else { "    " };
            let is_me = user.pub_id == state.my_pub_id;
            let style = if is_me {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(format!("{prefix}{name}")).style(style)
        })
        .collect();

    let list = List::new(items).block(block);
    f.render_widget(list, area);
}

fn draw_chat(f: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default().title("Chat").borders(Borders::ALL);

    let inner_height = area.height.saturating_sub(2) as usize;
    let total = state.messages.len();

    // Apply scroll offset: 0 = bottom, higher = older
    let scroll = state.scroll_offset.min(total.saturating_sub(inner_height));
    let end = total.saturating_sub(scroll);
    let start = end.saturating_sub(inner_height);

    let lines: Vec<Line> = state
        .messages
        .iter()
        .skip(start)
        .take(end - start)
        .map(|msg| format_chat_line(msg, state))
        .collect();

    let para = Paragraph::new(Text::from(lines))
        .block(block)
        .wrap(Wrap { trim: false });

    f.render_widget(para, area);
}

fn format_chat_line(line: &ChatLine, state: &AppState) -> Line<'static> {
    match line {
        ChatLine::Chat { from, text, ts } => {
            let time_str = ts.format("%H:%M").to_string();
            let name = state.display_name(from);
            let is_me = *from == state.my_pub_id;
            let name_style = if is_me {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Cyan)
            };
            // Strip ANSI + control chars from text before display
            let safe_text = strip_unsafe_chars(text);
            Line::from(vec![
                Span::styled(format!("{time_str} "), Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{name}: "), name_style),
                Span::raw(safe_text),
            ])
        }
        ChatLine::System(msg) => {
            let safe = strip_unsafe_chars(msg);
            Line::from(Span::styled(safe, Style::default().fg(Color::Yellow)))
        }
    }
}

/// Strip ANSI escape sequences and control characters from a string before rendering.
/// This prevents terminal injection via malicious relay messages.
pub fn strip_unsafe(s: &str) -> String {
    strip_unsafe_chars(s)
}

fn strip_unsafe_chars(s: &str) -> String {
    let mut out = String::with_capacity(s.len());

    // Escape-sequence parser state.
    enum EscState {
        Normal,
        // ESC seen; waiting for the byte that identifies the sequence type.
        EscSeen,
        // Inside a CSI (ESC [) or other non-OSC escape sequence.
        // Terminates on any ASCII letter.
        Csi { len: usize },
        // Inside an OSC sequence (ESC ]). Terminates on BEL (\x07), ST (ESC \),
        // or after 128 chars — beyond that a peer is trying to swallow content.
        Osc { last_was_esc: bool, len: usize },
    }

    let mut state = EscState::Normal;

    for ch in s.chars() {
        match state {
            EscState::Normal => {
                if ch == '\x1b' {
                    state = EscState::EscSeen;
                    continue;
                }
                // Strip Unicode bidi controls and zero-width chars (Unicode category Cf).
                // is_control() returns false for these — they must be checked explicitly.
                // A malicious peer can use these to reverse or reorder rendered text.
                let is_bidi_or_zw = matches!(
                    ch,
                    '\u{200B}'..='\u{200D}' // zero-width space / non-joiner / joiner
                        | '\u{200E}'        // left-to-right mark
                        | '\u{200F}'        // right-to-left mark
                        | '\u{202A}'..='\u{202E}' // LRE, RLE, PDF, LRO, RLO
                        | '\u{2060}'        // word joiner
                        | '\u{2066}'..='\u{2069}' // LRI, RLI, FSI, PDI
                        | '\u{FEFF}'        // BOM / zero-width no-break space
                );
                if is_bidi_or_zw {
                    continue;
                }
                // Allow printable chars and newlines; strip other control chars.
                if !ch.is_control() || ch == '\n' || ch == '\t' {
                    out.push(ch);
                }
            }

            EscState::EscSeen => {
                if ch == ']' {
                    // OSC sequence: ESC ] ... BEL  or  ESC ] ... ESC \
                    state = EscState::Osc {
                        last_was_esc: false,
                        len: 0,
                    };
                } else {
                    // All other sequences (CSI = '[', plus single-char Fe sequences).
                    state = EscState::Csi { len: 0 };
                    // If this char is already a terminator (a letter), close immediately.
                    if ch.is_ascii_alphabetic() {
                        state = EscState::Normal;
                    }
                }
                continue;
            }

            EscState::Csi { ref mut len } => {
                *len += 1;
                // End of CSI/ANSI escape is an ASCII letter.
                if ch.is_ascii_alphabetic() {
                    state = EscState::Normal;
                    continue;
                }
                // Cap: a real ANSI escape never exceeds 64 chars; beyond this,
                // the peer is malicious and trying to swallow message content.
                // Reset escape mode and emit the current char normally.
                if *len > 64 {
                    state = EscState::Normal;
                    // Fall through — emit ch as a normal character below by
                    // reprocessing it. Since we're in a match arm, we push directly.
                    if !ch.is_control() || ch == '\n' || ch == '\t' {
                        out.push(ch);
                    }
                }
                // Otherwise still inside the escape — swallow the char.
            }

            EscState::Osc {
                ref mut last_was_esc,
                ref mut len,
            } => {
                *len += 1;
                if ch == '\x07' {
                    // BEL terminates an OSC sequence.
                    state = EscState::Normal;
                } else if *last_was_esc && ch == '\\' {
                    // ST = ESC \ terminates an OSC sequence.
                    state = EscState::Normal;
                } else if *len > 128 {
                    // Cap: a real OSC never exceeds 128 chars; beyond this the
                    // peer is malicious and trying to swallow subsequent content.
                    // Reset and emit the current char normally.
                    state = EscState::Normal;
                    if !ch.is_control() || ch == '\n' || ch == '\t' {
                        out.push(ch);
                    }
                } else {
                    *last_was_esc = ch == '\x1b';
                    // Swallow chars inside the OSC payload.
                }
            }
        }
    }
    out
}

fn draw_input(f: &mut Frame, area: Rect, state: &AppState, display_start: usize) {
    let border_style = if state.focus == Focus::Input {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };
    let block = Block::default()
        .title("Input")
        .borders(Borders::ALL)
        .border_style(border_style);

    let para = Paragraph::new(&state.input[display_start..]).block(block);
    f.render_widget(para, area);
}

/// Walk backward from `cursor_byte` in `input`, accumulating display columns,
/// to find the byte offset where rendering should start so the cursor sits at
/// (or just inside) the right edge of a field that is `visible_width` columns wide.
fn find_display_start(input: &str, cursor_byte: usize, visible_width: usize) -> usize {
    let before_cursor = &input[..cursor_byte];
    let cursor_col = UnicodeWidthStr::width(before_cursor);
    if cursor_col <= visible_width {
        // Entire prefix fits — render from the beginning.
        return 0;
    }
    // Walk character boundaries backward until we've consumed `visible_width` columns.
    let mut remaining = visible_width;
    let mut start = cursor_byte;
    for (i, c) in before_cursor.char_indices().rev() {
        let w = UnicodeWidthChar::width(c).unwrap_or(0);
        if remaining < w {
            break;
        }
        remaining -= w;
        start = i;
    }
    start
}

fn draw_status(f: &mut Frame, area: Rect, state: &AppState) {
    let conn = state.connection.to_string();
    let mls = if state.mls_active {
        "MLS:active"
    } else {
        "MLS:setup"
    };
    let overlay = state.active_overlay().unwrap_or("");

    let status_text = if overlay.is_empty() {
        format!(" [{conn}] {mls}")
    } else {
        format!(" [{conn}] {mls} | {overlay}")
    };

    let para =
        Paragraph::new(status_text).style(Style::default().bg(Color::DarkGray).fg(Color::White));
    f.render_widget(para, area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_unsafe_chars_removes_ansi() {
        assert_eq!(strip_unsafe_chars("\x1b[31mred\x1b[0m"), "red");
    }

    #[test]
    fn strip_unsafe_chars_removes_control() {
        let result = strip_unsafe_chars("a\x07b\rc\nd");
        assert!(result.contains('a'));
        assert!(result.contains('b'));
        assert!(result.contains('c'));
        assert!(result.contains('\n'));
        assert!(!result.contains('\x07')); // bell stripped
        assert!(!result.contains('\r')); // CR stripped
    }

    #[test]
    fn strip_unsafe_chars_passes_unicode() {
        assert_eq!(
            strip_unsafe_chars("héllo wörld 日本語"),
            "héllo wörld 日本語"
        );
    }

    #[test]
    fn strip_unsafe_chars_caps_overlong_escape() {
        // A malicious peer sends ESC + 100 digits + 'm'. The first 64 body
        // chars are consumed as escape content, then in_escape resets and the
        // remaining 36 digits + 'm' are emitted as normal chars (digits are
        // not control chars). "hello" after that is fully preserved.
        let body = "0".repeat(100);
        let input = format!("\x1b{body}mhello");
        let result = strip_unsafe_chars(&input);
        // The first 65 chars after ESC (64 digits + the digit that triggered
        // the cap) are stripped; remaining 35 digits + 'm' + "hello" survive.
        assert!(
            result.ends_with("hello"),
            "hello must be preserved: {result:?}"
        );
        assert!(
            !result.starts_with('\x1b'),
            "ESC must not appear: {result:?}"
        );
    }

    #[test]
    fn strip_unsafe_chars_legitimate_long_escape() {
        // A real (but long) ANSI sequence like \x1b[1;2;3;4;5;6;7;8;9;10m
        // that stays within 64 chars should be stripped entirely.
        let seq = "\x1b[1;2;3;4;5;6;7;8;9;10m";
        assert!(seq.len() < 66, "test escape must be under 64 body chars");
        let result = strip_unsafe_chars(&format!("{seq}hello"));
        assert_eq!(result, "hello");
    }

    #[test]
    fn strip_unsafe_chars_strips_rlo() {
        // U+202E RIGHT-TO-LEFT OVERRIDE reverses text rendering — must be stripped.
        let input = "hello\u{202E}world";
        assert_eq!(strip_unsafe_chars(input), "helloworld");
    }

    #[test]
    fn strip_unsafe_chars_strips_bidi_controls() {
        // All bidi embedding/override controls must be stripped.
        for ch in [
            '\u{202A}', // LRE
            '\u{202B}', // RLE
            '\u{202C}', // PDF
            '\u{202D}', // LRO
            '\u{202E}', // RLO
            '\u{2066}', // LRI
            '\u{2067}', // RLI
            '\u{2068}', // FSI
            '\u{2069}', // PDI
            '\u{200E}', // LRM
            '\u{200F}', // RLM
        ] {
            let input = format!("a{ch}b");
            assert_eq!(
                strip_unsafe_chars(&input),
                "ab",
                "bidi char U+{:04X} must be stripped",
                ch as u32
            );
        }
    }

    #[test]
    fn strip_unsafe_chars_strips_zero_width() {
        for ch in [
            '\u{200B}', // zero-width space
            '\u{200C}', // zero-width non-joiner
            '\u{200D}', // zero-width joiner
            '\u{2060}', // word joiner
            '\u{FEFF}', // BOM
        ] {
            let input = format!("a{ch}b");
            assert_eq!(
                strip_unsafe_chars(&input),
                "ab",
                "zero-width char U+{:04X} must be stripped",
                ch as u32
            );
        }
    }

    #[test]
    fn strip_unsafe_chars_preserves_normal_unicode() {
        // Ensure the bidi filter does not accidentally strip legitimate chars.
        assert_eq!(
            strip_unsafe_chars("héllo\u{2019}s café 日本語"),
            "héllo\u{2019}s café 日本語"
        );
    }

    #[test]
    fn strip_unsafe_chars_caps_overlong_osc() {
        // An unterminated ESC ] with no BEL or ST must not swallow all subsequent
        // content. After the 128-char cap the rest of the string must be preserved.
        let osc_body = "X".repeat(200);
        let input = format!("\x1b]{osc_body}hello");
        let result = strip_unsafe_chars(&input);
        assert!(
            result.ends_with("hello"),
            "content after overlong OSC must be preserved: {result:?}"
        );
        assert!(
            !result.starts_with('\x1b'),
            "ESC must not appear in output: {result:?}"
        );
    }

    #[test]
    fn strip_unsafe_chars_osc_terminated_by_bel() {
        // ESC ] <payload> BEL — BEL terminates; following text is preserved.
        let input = "\x1b]0;window title\x07visible text";
        assert_eq!(strip_unsafe_chars(input), "visible text");
    }

    #[test]
    fn strip_unsafe_chars_osc_terminated_by_st() {
        // ESC ] <payload> ESC \ — ST terminates; following text is preserved.
        let input = "\x1b]0;window title\x1b\\visible text";
        assert_eq!(strip_unsafe_chars(input), "visible text");
    }
}
