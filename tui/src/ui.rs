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
    let mut in_escape = false;
    let mut escape_len: usize = 0;
    for ch in s.chars() {
        if ch == '\x1b' {
            in_escape = true;
            escape_len = 0;
            continue;
        }
        if in_escape {
            escape_len += 1;
            // End of ANSI escape is a letter (a-zA-Z)
            if ch.is_ascii_alphabetic() {
                in_escape = false;
                escape_len = 0;
                continue;
            }
            // Cap: a real ANSI escape never exceeds 64 chars; beyond this,
            // the peer is malicious and trying to swallow message content.
            // Reset escape mode and emit the current char normally.
            if escape_len > 64 {
                in_escape = false;
                escape_len = 0;
                // Fall through to the normal char handling below.
            } else {
                continue;
            }
        }
        // Allow printable chars, spaces, and newlines; strip other control chars
        if !ch.is_control() || ch == '\n' || ch == '\t' {
            out.push(ch);
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
}
